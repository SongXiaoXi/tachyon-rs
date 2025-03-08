use proc_macro::Group;
use proc_macro::Ident;
use proc_macro::Literal;
use proc_macro::Punct;
use proc_macro::Spacing;
use proc_macro::Span;
use proc_macro::TokenStream;
use proc_macro::Delimiter;
use proc_macro::TokenTree;

#[proc_macro_attribute]
pub fn loop_unroll(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_iter: Vec<_> = attr.into_iter().collect();
    let idx_var_name = if let TokenTree::Ident(ident) = &attr_iter[0] {
        ident.clone()
    } else {
        panic!("First argument must be an identifier");
    };
    let idx_start = if let TokenTree::Literal(ident) = &attr_iter[2] {
        ident.clone()
    } else {
        panic!("Second argument must be an integer literal");
    };
    let loop_count = if let TokenTree::Literal(ident) = attr_iter[4].clone() {
        ident
    } else {
        panic!("Third argument must be an integer identifier");
    };
    let loop_step = if attr_iter.len() >= 6 {
        if let TokenTree::Literal(ident) = attr_iter[6].clone() {
            ident
        } else {
            panic!("Fourth argument must be an integer identifier");
        }
    } else {
        Literal::usize_unsuffixed(1)
    };

    // test if idx_var_name is "_"
    let no_need_idx_var = idx_var_name.to_string() == "_";

    let mut output = TokenStream::new();

    if !no_need_idx_var {
        // output token "let" "mut" "idx_var_name" "=" "idx_start"";"
        output.extend(TokenStream::from(TokenTree::Ident(Ident::new("let", Span::call_site()))));
        output.extend(TokenStream::from(TokenTree::Ident(Ident::new("mut", Span::call_site()))));
        output.extend(TokenStream::from(TokenTree::Ident(idx_var_name.clone())));
        output.extend(TokenStream::from(TokenTree::Punct(Punct::new('=', Spacing::Alone))));
        output.extend(TokenStream::from(TokenTree::Literal(idx_start)));
        output.extend(TokenStream::from(TokenTree::Punct(Punct::new(';', Spacing::Alone))));
    }

    // parse loop_count as usize
    let loop_count = loop_count.to_string().parse::<usize>().unwrap();

    let mut block = TokenStream::new();
    // ignore Ident before brace
    for tt in item.clone().into_iter() {
        if let TokenTree::Group(ref group) = tt {
            if group.delimiter() == Delimiter::Brace {
                block = TokenStream::from(tt);
                break;
            }
        }
    }

    let iter = block.into_iter();

    for _ in 0..(loop_count - 1) {
        let item = iter.clone();
        for tt in item {
            output.extend(TokenStream::from(tt));
        }
        if !no_need_idx_var {
            // output token "idx_var_name" "+=" "loop_step"";"
            output.extend(TokenStream::from(TokenTree::Ident(idx_var_name.clone())));
            output.extend(TokenStream::from(TokenTree::Punct(Punct::new('+', Spacing::Joint))));
            output.extend(TokenStream::from(TokenTree::Punct(Punct::new('=', Spacing::Alone))));
            output.extend(TokenStream::from(TokenTree::Literal(loop_step.clone())));
            output.extend(TokenStream::from(TokenTree::Punct(Punct::new(';', Spacing::Alone))));
        }
    }

    for tt in iter {
        output.extend(TokenStream::from(tt));
    }

    output =TokenStream::from(TokenTree::Group(Group::new(Delimiter::Brace, output)));

    // println!("output: {:?}", output.to_string());

    output
}