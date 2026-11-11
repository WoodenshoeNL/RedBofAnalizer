//! OC2 Stage1 (`.s1.py`) wrapper driver.
//!
//! OC2 exposes BOFs to operators through Stage1 Python scripts (`*.s1.py`)
//! that subclass `BaseBOFTask`. The wrapper is the authoritative spec of
//! how arguments are packed: `_encode_arguments_bof()` returns an ordered
//! list of `(BOFArgumentEncoding, value)` pairs that OC2 serializes in the
//! canonical bof_pack format (see [`crate::beacon::argspec`]).
//!
//! This module statically extracts that spec from the script source — no
//! Python runtime — so the analyzer can reproduce OC2's exact packed buffer:
//!
//! - `super().__init__("cmd", base_binary_name="bin")` → command and BOF
//!   file name (`bin.x64.o`).
//! - `self.parser.add_argument(...)` → option/positional names, `type=int`,
//!   `action="store_true"`, and literal defaults.
//! - `_encode_arguments_bof` return list → ordered packed entries with
//!   expressions mapped back to parser arguments, file uploads
//!   (`get_file_by_name("name")` / `payload.content`), literals, and
//!   `1 if args.flag else 0` boolean conversions.
//! - `get_file_by_name("name")` → accepted `--file name=path` uploads.
//!
//! Unsupported expressions (string interpolation, computed values) produce
//! a [`S1Error`] naming the offending line rather than a wrong pack.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::core::executor::argspec::{pack, ArgType, ArgValue};

/// Errors while parsing or applying a `.s1.py` wrapper.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum S1Error {
    #[error("could not read script: {0}")]
    Io(String),
    #[error("no BaseBOFTask subclass found in script")]
    NoTaskClass,
    #[error("no super().__init__(...) with command name found")]
    NoInit,
    #[error("no _encode_arguments_bof return list found")]
    NoEncodeList,
    #[error("unsupported expression in _encode_arguments_bof: {0}")]
    UnsupportedExpression(String),
    #[error("encode list references unknown argument '{0}'")]
    UnknownArgument(String),
    #[error("unknown option '{0}'")]
    UnknownOption(String),
    #[error("missing value for option '{0}'")]
    MissingValue(String),
    #[error("argument '{name}' expects {expected}, got '{got}'")]
    TypeConversion {
        name: String,
        expected: &'static str,
        got: String,
    },
    #[error("missing uploaded file for element '{0}' (pass --file {0}=<path>)")]
    MissingFile(String),
    #[error("too many positional arguments")]
    TooManyPositional,
}

/// A parser argument extracted from `add_argument(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S1Arg {
    /// Longest flag (`--timeout`) or positional name (`token`).
    pub name: String,
    /// All option strings, e.g. `["--timeout", "-t"]`; empty for positionals.
    pub flags: Vec<String>,
    pub kind: S1ArgKind,
    /// Literal default (`None` → type zero-value at pack time).
    pub default: Option<S1Literal>,
    /// `choices=[...]` values, if declared.
    pub choices: Vec<String>,
}

/// Parsed type of a parser argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1ArgKind {
    /// `type=int` → numeric option.
    Int,
    /// `action="store_true"` → boolean flag.
    Bool,
    /// Plain string option or positional.
    Str,
}

/// A Python literal understood by the extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S1Literal {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// A packed entry in `_encode_arguments_bof`'s return list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeSource {
    /// Value comes from a parser argument (`args.<name>`); bool flags pack
    /// as 1/0 ints.
    Arg(String),
    /// `1 if args.<flag> else 0` (or reversed).
    FlagAsInt(String),
    /// Uploaded file content for a `get_file_by_name("<element>")` element.
    File(String),
    /// Literal value.
    Literal(S1Literal),
}

/// A parsed `.s1.py` wrapper spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S1Spec {
    /// OC2 command name (first `super().__init__` positional).
    pub command: String,
    /// BOF file stem (`base_binary_name`, defaults to command).
    pub base_binary_name: String,
    /// Optional subdirectory (`base_binary_path`).
    pub base_binary_path: Option<String>,
    /// Parser arguments in declaration order (positionals and options).
    pub args: Vec<S1Arg>,
    /// Packed entries in `_encode_arguments_bof` order.
    pub encode: Vec<(ArgType, EncodeSource)>,
    /// Names accepted by `get_file_by_name(...)`.
    pub file_elements: Vec<String>,
}

impl S1Spec {
    /// The bof_pack format string for this spec (e.g. `"bzi"`).
    pub fn format_string(&self) -> String {
        self.encode.iter().map(|(t, _)| t.as_char()).collect()
    }

    /// Parse a `.s1.py` file.
    pub fn from_file(path: &Path) -> Result<Self, S1Error> {
        let src = std::fs::read_to_string(path).map_err(|e| S1Error::Io(e.to_string()))?;
        Self::from_source(&src)
    }

    /// Parse `.s1.py` source text.
    pub fn from_source(src: &str) -> Result<Self, S1Error> {
        if !src.contains("BaseBOFTask") {
            return Err(S1Error::NoTaskClass);
        }
        let (command, base_binary_name, base_binary_path) = parse_init(src)?;
        let args = parse_add_arguments(src);
        let encode = parse_encode_list(src)?;
        let file_elements = parse_file_elements(src);

        // Cross-check: encode entries referencing args must exist.
        for (ty, source) in &encode {
            let _ = ty;
            match source {
                EncodeSource::Arg(name) | EncodeSource::FlagAsInt(name) => {
                    if !args.iter().any(|a| &a.name == name) {
                        return Err(S1Error::UnknownArgument(name.clone()));
                    }
                }
                EncodeSource::File(el) => {
                    if el != PLACEHOLDER_FILE && !file_elements.iter().any(|f| f == el) {
                        return Err(S1Error::UnknownArgument(el.clone()));
                    }
                }
                EncodeSource::Literal(_) => {}
            }
        }

        Ok(S1Spec {
            command,
            base_binary_name,
            base_binary_path,
            args,
            encode,
            file_elements,
        })
    }

    /// Resolve operator argv (as OC2 passes it after split_arguments) plus
    /// uploaded file contents into the packed bof_pack buffer.
    ///
    /// `files` maps `get_file_by_name` element names to their bytes.
    pub fn pack_arguments(
        &self,
        argv: &[String],
        files: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, S1Error> {
        use std::collections::HashMap;

        // values by canonical name
        let mut values: HashMap<String, S1Literal> = HashMap::new();

        // Seed with declared defaults.
        for a in &self.args {
            if let Some(d) = &a.default {
                values.insert(a.name.clone(), d.clone());
            }
        }

        // Walk argv: options by flag, positionals in declaration order.
        let positionals: Vec<&S1Arg> = self.args.iter().filter(|a| a.flags.is_empty()).collect();
        let mut next_positional = 0usize;
        let mut i = 0usize;
        while i < argv.len() {
            let tok = &argv[i];
            if let Some(flag) = tok.strip_prefix('-') {
                let arg = self
                    .args
                    .iter()
                    .find(|a| {
                        a.flags
                            .iter()
                            .any(|f| f.trim_start_matches('-') == flag.trim_start_matches('-'))
                    })
                    .ok_or_else(|| S1Error::UnknownOption(tok.clone()))?;
                if arg.kind == S1ArgKind::Bool {
                    values.insert(arg.name.clone(), S1Literal::Bool(true));
                    i += 1;
                    continue;
                }
                i += 1;
                let raw = argv
                    .get(i)
                    .ok_or_else(|| S1Error::MissingValue(tok.clone()))?;
                values.insert(arg.name.clone(), coerce(arg, raw)?);
                i += 1;
            } else {
                let arg = positionals
                    .get(next_positional)
                    .ok_or(S1Error::TooManyPositional)?;
                next_positional += 1;
                if !arg.choices.is_empty() && !arg.choices.iter().any(|c| c == tok) {
                    return Err(S1Error::TypeConversion {
                        name: arg.name.clone(),
                        expected: "one of the declared choices",
                        got: tok.clone(),
                    });
                }
                values.insert(arg.name.clone(), coerce(arg, tok)?);
                i += 1;
            }
        }

        // Build typed values in encode-list order.
        let mut typed = Vec::new();
        for (ty, source) in &self.encode {
            let value = match source {
                EncodeSource::Arg(name) => {
                    let lit = values.get(name);
                    match ty {
                        ArgType::Int | ArgType::Short => {
                            let n = match lit {
                                Some(S1Literal::Int(n)) => *n,
                                Some(S1Literal::Bool(b)) => *b as i64,
                                Some(S1Literal::Str(s)) => {
                                    s.parse::<i64>().map_err(|_| S1Error::TypeConversion {
                                        name: name.clone(),
                                        expected: "int",
                                        got: s.clone(),
                                    })?
                                }
                                None => 0,
                            };
                            if *ty == ArgType::Short {
                                ArgValue::Short(n as i16)
                            } else {
                                ArgValue::Int(n as i32)
                            }
                        }
                        ArgType::Str => ArgValue::Str(match lit {
                            Some(S1Literal::Str(s)) => s.clone(),
                            Some(S1Literal::Int(n)) => n.to_string(),
                            Some(S1Literal::Bool(b)) => b.to_string(),
                            None => String::new(),
                        }),
                        ArgType::WStr => ArgValue::WStr(match lit {
                            Some(S1Literal::Str(s)) => s.clone(),
                            Some(S1Literal::Int(n)) => n.to_string(),
                            Some(S1Literal::Bool(b)) => b.to_string(),
                            None => String::new(),
                        }),
                        ArgType::Buffer => ArgValue::Buffer(match lit {
                            Some(S1Literal::Str(s)) => s.clone().into_bytes(),
                            _ => Vec::new(),
                        }),
                    }
                }
                EncodeSource::FlagAsInt(name) => {
                    let b = matches!(values.get(name), Some(S1Literal::Bool(true)));
                    if *ty == ArgType::Short {
                        ArgValue::Short(b as i16)
                    } else {
                        ArgValue::Int(b as i32)
                    }
                }
                EncodeSource::File(element) => ArgValue::Buffer(
                    files
                        .get(element)
                        .cloned()
                        .ok_or_else(|| S1Error::MissingFile(element.clone()))?,
                ),
                EncodeSource::Literal(lit) => match (ty, lit) {
                    (ArgType::Int, S1Literal::Int(n)) => ArgValue::Int(*n as i32),
                    (ArgType::Int, S1Literal::Bool(b)) => ArgValue::Int(*b as i32),
                    (ArgType::Short, S1Literal::Int(n)) => ArgValue::Short(*n as i16),
                    (ArgType::Str, S1Literal::Str(s)) => ArgValue::Str(s.clone()),
                    (ArgType::WStr, S1Literal::Str(s)) => ArgValue::WStr(s.clone()),
                    (t, l) => {
                        return Err(S1Error::UnsupportedExpression(format!(
                            "literal {:?} for type {}",
                            l,
                            t.as_char()
                        )))
                    }
                },
            };
            typed.push(value);
        }

        pack(
            Some(&self.encode.iter().map(|(t, _)| *t).collect::<Vec<_>>()),
            &typed,
        )
        .map_err(|e| S1Error::UnsupportedExpression(e.to_string()))
    }

    /// Locate the BOF binary relative to the wrapper script's directory.
    pub fn resolve_bof(&self, script_dir: &Path, x86: bool) -> PathBuf {
        let mut p = script_dir.to_path_buf();
        if let Some(sub) = &self.base_binary_path {
            p.push(sub);
        }
        p.push(format!(
            "{}.{}",
            self.base_binary_name,
            if x86 { "x86.o" } else { "x64.o" }
        ));
        p
    }
}

fn coerce(arg: &S1Arg, raw: &str) -> Result<S1Literal, S1Error> {
    match arg.kind {
        S1ArgKind::Int => {
            raw.parse::<i64>()
                .map(S1Literal::Int)
                .map_err(|_| S1Error::TypeConversion {
                    name: arg.name.clone(),
                    expected: "int",
                    got: raw.to_string(),
                })
        }
        S1ArgKind::Str => Ok(S1Literal::Str(raw.to_string())),
        S1ArgKind::Bool => Ok(S1Literal::Bool(matches!(
            raw,
            "1" | "true" | "True" | "yes"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Static extraction helpers
// ---------------------------------------------------------------------------

fn parse_init(src: &str) -> Result<(String, String, Option<String>), S1Error> {
    // Scan every super().__init__( call in the file (a wrapper may define
    // several task classes or use a factory with non-literal command names).
    // Prefer the first literal command name; take the first literal
    // base_binary_name/base_binary_path anywhere.
    let mut command: Option<String> = None;
    let mut base_binary_name: Option<String> = None;
    let mut base_binary_path: Option<String> = None;

    for (start, inner) in find_calls(src, "super().__init__(") {
        let _ = start;
        let parts = split_top_level_commas(&inner);
        if parts.is_empty() {
            continue;
        }
        if command.is_none() {
            if let Some(s) = parse_str_literal(&parts[0]) {
                command = Some(s);
            }
        }
        for kv in &parts[1..] {
            if let Some((_, v)) = kv.split_once("base_binary_name=") {
                if base_binary_name.is_none() {
                    base_binary_name = parse_str_literal(v.trim());
                }
            } else if let Some((_, v)) = kv.split_once("base_binary_path=") {
                if base_binary_path.is_none() {
                    base_binary_path = parse_str_literal(v.trim());
                }
            }
        }
    }

    let command = command
        .clone()
        .or_else(|| base_binary_name.clone())
        .ok_or(S1Error::NoInit)?;
    let base_binary_name = base_binary_name.unwrap_or_else(|| command.clone());
    Ok((command, base_binary_name, base_binary_path))
}

/// Split on commas that are not nested inside (), [], {} or quotes.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => {
                    out.push(cur.clone());
                    cur.clear();
                }
                _ => cur.push(c),
            },
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn parse_str_literal(s: &str) -> Option<String> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

/// Extract a Python literal (str/int/bool/None) from a default= position.
fn parse_py_literal(s: &str) -> Option<S1Literal> {
    let s = s.trim();
    if s == "None" {
        return None;
    }
    if let Some(str_val) = parse_str_literal(s) {
        return Some(S1Literal::Str(str_val));
    }
    if s == "True" {
        return Some(S1Literal::Bool(true));
    }
    if s == "False" {
        return Some(S1Literal::Bool(false));
    }
    s.parse::<i64>().ok().map(S1Literal::Int)
}

fn parse_add_arguments(src: &str) -> Vec<S1Arg> {
    let mut out = Vec::new();
    for (_, call) in find_calls(src, "self.parser.add_argument(") {
        let parts = split_top_level_commas(&call);
        if parts.is_empty() {
            continue;
        }
        let mut flags: Vec<String> = Vec::new();
        let mut positional: Option<String> = None;
        for p in &parts {
            let p = p.trim();
            if let Some(name) = parse_str_literal(p) {
                if name.starts_with('-') {
                    flags.push(name);
                } else if positional.is_none() {
                    positional = Some(name);
                }
                continue;
            }
            break; // first kwarg — stop scanning positionals
        }
        let name = match (&positional, flags.first()) {
            (Some(p), _) => p.clone(),
            (None, Some(f)) => f.trim_start_matches('-').to_string(),
            (None, None) => continue,
        };

        let mut kind = S1ArgKind::Str;
        let mut default: Option<S1Literal> = None;
        let mut choices = Vec::new();
        for p in &parts {
            let p = p.trim();
            if let Some(v) = p.strip_prefix("type=") {
                if v.trim() == "int" {
                    kind = S1ArgKind::Int;
                }
            } else if let Some(v) = p.strip_prefix("action=") {
                if parse_str_literal(v).as_deref() == Some("store_true") {
                    kind = S1ArgKind::Bool;
                }
            } else if let Some(v) = p.strip_prefix("default=") {
                default = parse_py_literal(v);
            } else if let Some(v) = p.strip_prefix("choices=") {
                choices = parse_choices_list(v);
            }
        }

        out.push(S1Arg {
            name,
            flags,
            kind,
            default,
            choices,
        });
    }
    out
}

fn parse_choices_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let inner = match s
        .strip_prefix('[')
        .and_then(|t| t.rfind(']').map(|i| &t[..i]))
    {
        Some(i) => i,
        None => return Vec::new(),
    };
    split_top_level_commas(inner)
        .iter()
        .filter_map(|p| parse_str_literal(p))
        .collect()
}

fn parse_file_elements(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_, call) in find_calls(src, "get_file_by_name(") {
        if let Some(s) = parse_str_literal(call.split(',').next().unwrap_or("")) {
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// Find call sites of `prefix(` and return (byte offset of the open paren's
/// content start, balanced content up to the matching close paren).
fn find_calls(src: &str, prefix: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = src[search_from..].find(prefix) {
        let start = search_from + rel + prefix.len();
        let mut depth = 1i32;
        let mut quote: Option<char> = None;
        let mut i = start;
        while i < bytes.len() && depth > 0 {
            let c = bytes[i] as char;
            match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                }
                None => match c {
                    '\'' | '"' => quote = Some(c),
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                },
            }
            if depth > 0 {
                i += 1;
            }
        }
        if depth == 0 {
            out.push((start, src[start..i].to_string()));
        }
        search_from = start;
    }
    out
}

/// Extract the ordered encode list from `_encode_arguments_bof`.
fn parse_encode_list(src: &str) -> Result<Vec<(ArgType, EncodeSource)>, S1Error> {
    let fn_idx = src
        .find("def _encode_arguments_bof")
        .ok_or(S1Error::NoEncodeList)?;
    let body = &src[fn_idx..];
    let ret_idx = body.find("return [").ok_or(S1Error::NoEncodeList)?;
    let open = fn_idx + ret_idx + "return [".len();
    // Balanced scan for the closing ']'
    let bytes = src.as_bytes();
    let mut depth = 1i32;
    let mut quote: Option<char> = None;
    let mut i = open;
    while i < bytes.len() && depth > 0 {
        let c = bytes[i] as char;
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            },
        }
        if depth > 0 {
            i += 1;
        }
    }
    if depth != 0 {
        return Err(S1Error::NoEncodeList);
    }
    let list_body = &src[open..i];

    let mut out = Vec::new();
    for entry in split_top_level_commas(list_body) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Entry: (BOFArgumentEncoding.XXX, expr) — possibly commented tail.
        let inner = entry
            .strip_prefix('(')
            .and_then(|t| t.rfind(')').map(|p| &t[..p]))
            .ok_or_else(|| S1Error::UnsupportedExpression(entry.to_string()))?;
        let parts = split_top_level_commas(inner);
        if parts.len() < 2 {
            return Err(S1Error::UnsupportedExpression(entry.to_string()));
        }
        let ty = parse_encoding_name(&parts[0])?;
        let expr = collapse_ws(&parts[1]);
        let source = map_expression(&expr)?;
        out.push((ty, source));
    }
    Ok(out)
}

fn parse_encoding_name(s: &str) -> Result<ArgType, S1Error> {
    let s = collapse_ws(s);
    let suffix = s
        .strip_prefix("BOFArgumentEncoding.")
        .ok_or_else(|| S1Error::UnsupportedExpression(s.clone()))?;
    match suffix.trim() {
        "INT" => Ok(ArgType::Int),
        "SHORT" => Ok(ArgType::Short),
        "STR" => Ok(ArgType::Str),
        "WSTR" => Ok(ArgType::WStr),
        "BUFFER" | "BIN" => Ok(ArgType::Buffer),
        other => Err(S1Error::UnsupportedExpression(format!(
            "BOFArgumentEncoding.{}",
            other
        ))),
    }
}

fn collapse_ws(s: &str) -> String {
    // Drop trailing comments, then join internal whitespace runs.
    let no_comment = s.split_once('#').map(|(a, _)| a).unwrap_or(s);
    no_comment.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn map_expression(expr: &str) -> Result<EncodeSource, S1Error> {
    // Literal int
    if let Ok(n) = expr.parse::<i64>() {
        return Ok(EncodeSource::Literal(S1Literal::Int(n)));
    }
    if let Some(s) = parse_str_literal(expr) {
        return Ok(EncodeSource::Literal(S1Literal::Str(s)));
    }
    // "1 if args.flag else 0" / "0 if args.flag else 1"
    if expr.starts_with("1 if ") {
        if let Some(name) = extract_args_name(&expr["1 if ".len()..]) {
            return Ok(EncodeSource::FlagAsInt(name));
        }
    }
    if expr.starts_with("0 if ") {
        if let Some(name) = extract_args_name(&expr["0 if ".len()..]) {
            return Ok(EncodeSource::FlagAsInt(name));
        }
    }
    // args.name / self.args.name
    if let Some(name) = extract_args_name(expr) {
        return Ok(EncodeSource::Arg(name));
    }
    // File content expressions: "<var>.content" — the element name is bound
    // by `var = self.get_file_by_name("<el>")` earlier in the method; we map
    // any *.content reference to the single declared file element when there
    // is exactly one (the overwhelmingly common shape).
    if expr.ends_with(".content") {
        return Ok(EncodeSource::File(PLACEHOLDER_FILE.into()));
    }
    Err(S1Error::UnsupportedExpression(expr.to_string()))
}

/// Pull the argument name out of `args.foo ...` / `parser_arguments.foo ...`.
fn extract_args_name(expr: &str) -> Option<String> {
    let rest = expr
        .strip_prefix("args.")
        .or_else(|| expr.strip_prefix("parser_arguments."))
        .or_else(|| expr.strip_prefix("self.args."))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Placeholder element name for `*.content` expressions; resolved to the
/// single declared file element during `from_source` cross-check when only
/// one file element exists.
const PLACEHOLDER_FILE: &str = "\0content";

/// Resolve placeholder file references and validate against declared uploads.
fn finalize_spec(spec: &mut S1Spec) -> Result<(), S1Error> {
    for (_, source) in spec.encode.iter_mut() {
        if matches!(source, EncodeSource::File(f) if f == PLACEHOLDER_FILE) {
            if spec.file_elements.len() != 1 {
                return Err(S1Error::UnsupportedExpression(
                    "multiple get_file_by_name elements; use a single upload or extend the parser"
                        .into(),
                ));
            }
            *source = EncodeSource::File(spec.file_elements[0].clone());
        }
    }
    Ok(())
}

/// Parse a wrapper and return a spec with placeholders resolved.
pub fn parse_wrapper(path: &Path) -> Result<S1Spec, S1Error> {
    let mut spec = S1Spec::from_file(path)?;
    finalize_spec(&mut spec)?;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/s1")
            .join(name)
    }

    #[test]
    fn parses_race_wrapper() {
        let spec = parse_wrapper(&fixture("intune_race_bof.s1.py")).unwrap();
        assert_eq!(spec.command, "intune-race");
        assert_eq!(spec.base_binary_name, "race");
        assert_eq!(spec.format_string(), "bzi");
        assert_eq!(spec.file_elements, vec!["payload_dll".to_string()]);

        // timeout option parsed with int type and default
        let timeout = spec.args.iter().find(|a| a.name == "timeout").unwrap();
        assert_eq!(timeout.kind, S1ArgKind::Int);
        assert_eq!(timeout.default, Some(S1Literal::Int(120)));
        let plugin = spec.args.iter().find(|a| a.name == "plugin").unwrap();
        assert_eq!(plugin.default, Some(S1Literal::Str("nsExec.dll".into())));

        // encode list: file, plugin arg, timeout arg
        assert_eq!(
            spec.encode,
            vec![
                (ArgType::Buffer, EncodeSource::File("payload_dll".into())),
                (ArgType::Str, EncodeSource::Arg("plugin".into())),
                (ArgType::Int, EncodeSource::Arg("timeout".into())),
            ]
        );
    }

    #[test]
    fn race_wrapper_packs_golden_bytes() {
        let spec = parse_wrapper(&fixture("intune_race_bof.s1.py")).unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert("payload_dll".to_string(), vec![0x4D, 0x5A, 0x90, 0x00]);
        let argv: Vec<String> = vec!["--timeout".into(), "300".into()];
        let buf = spec.pack_arguments(&argv, &files).unwrap();

        let mut expect: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x4D, 0x5A, 0x90, 0x00];
        expect.extend_from_slice(&[0x0B, 0x00, 0x00, 0x00]); // nsExec.dll\0
        expect.extend_from_slice(b"nsExec.dll\0");
        expect.extend_from_slice(&300i32.to_le_bytes());
        assert_eq!(buf, expect);
    }

    #[test]
    fn race_wrapper_defaults_and_missing_file() {
        let spec = parse_wrapper(&fixture("intune_race_bof.s1.py")).unwrap();
        let argv: Vec<String> = vec![];
        let err = spec.pack_arguments(&argv, &Default::default()).unwrap_err();
        assert!(matches!(err, S1Error::MissingFile(e) if e == "payload_dll"));

        let mut files = std::collections::HashMap::new();
        files.insert("payload_dll".to_string(), vec![0xAA]);
        let buf = spec.pack_arguments(&argv, &files).unwrap();
        // default timeout 120 packed
        assert_eq!(&buf[buf.len() - 4..], &120i32.to_le_bytes());
    }

    #[test]
    fn parses_checkin_wrapper_with_positionals() {
        // The checkin wrapper builds its command name via a factory and only
        // exposes literal names on the secondary task class; the parser
        // merges literal candidates across all super().__init__ calls.
        let spec = parse_wrapper(&fixture("intune_checkin_bof.s1.py")).unwrap();
        assert_eq!(spec.command, "intune-checkin-nt");
        assert_eq!(spec.base_binary_name, "checkin");
        assert!(!spec.format_string().is_empty());
    }

    #[test]
    fn parses_all_shipped_wrappers() {
        for name in [
            "intune_apps_bof.s1.py",
            "intune_checkin_bof.s1.py",
            "intune_exchange_bof.s1.py",
            "intune_race_bof.s1.py",
        ] {
            let spec = parse_wrapper(&fixture(name)).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert!(!spec.base_binary_name.is_empty(), "{}", name);
            assert!(!spec.format_string().is_empty(), "{}", name);
        }
    }

    #[test]
    fn unknown_option_rejected() {
        let spec = parse_wrapper(&fixture("intune_race_bof.s1.py")).unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert("payload_dll".to_string(), vec![0xAA]);
        let argv: Vec<String> = vec!["--nope".into()];
        let err = spec.pack_arguments(&argv, &files).unwrap_err();
        assert!(matches!(err, S1Error::UnknownOption(o) if o == "--nope"));
    }
}
