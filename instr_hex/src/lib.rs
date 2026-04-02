
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, LitStr, Token,
};
use std::process::Command;

struct InstrHexInput {
    insts: Punctuated<LitStr, Token![,]>,
    feature: Option<LitStr>,
}

impl Parse for InstrHexInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut insts = Punctuated::new();
        while !input.peek(Ident) {
            let lit: LitStr = input.parse()?;
            insts.push(lit);
            if input.peek(Token![,]) {
                let _comma: Token![,] = input.parse()?;
            }
            if input.is_empty() {
                break;
            }
        }
        let feature = if input.peek(Ident) {
            let key: Ident = input.parse()?;
            if key == "target_feature" {
                let _: Token![=] = input.parse()?;
                let lit: LitStr = input.parse()?;
                Some(lit)
            } else {
                return Err(syn::Error::new(key.span(), "expected `target_feature`"));
            }
        } else {
            None
        };
        Ok(InstrHexInput { insts, feature })
    }
}

#[proc_macro]
pub fn instr_hex(input: TokenStream) -> TokenStream {
    use std::io::Write;
    let InstrHexInput { insts, feature } = parse_macro_input!(input as InstrHexInput);

    let mut outs = Vec::new();
    for lit in insts.iter() {
        let asm = lit.value();
        let mut cmd = Command::new("llvm-mc");
        cmd.arg("-triple=aarch64").arg("-show-encoding");
        if let Some(feat) = &feature {
            cmd.arg(format!("-mattr=+{}", feat.value()));
        }

        let mut llvm_mc = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn llvm-mc; make sure it's in $PATH");
        llvm_mc.stdin.as_mut().unwrap().write_all(asm.as_bytes()).unwrap();
        llvm_mc.stdin.as_mut().unwrap().flush().unwrap();
        let out = llvm_mc.wait_with_output().expect("failed to read stdout");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let hex = stdout
            .split("encoding:")
            .nth(1)
            .and_then(|s| s.split('[').nth(1))
            .and_then(|s| s.split(']').next())
            .map(|s| {
                s.split(',')
                    .map(|b| b.trim().trim_start_matches("0x"))
                    .rev()
                    .collect::<Vec<_>>()
                    .join("")
            })
            .expect("unable to parse llvm-mc output");

        outs.push(format!(".inst 0x{}\n", hex));
    }

    let combined = outs.into_iter().fold(String::new(), |mut acc, l| {
        acc.push_str(&l);
        acc
    });
    let combined_lit = Literal::string(&combined);

    TokenStream::from(quote! {
        #combined_lit
    })
}