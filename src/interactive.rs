use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::{analyze_dump, check_output, path_exists, Options};

pub(crate) fn run() -> io::Result<()> {
    let paths = choose_paths(&mut io::stdin().lock(), &mut io::stdout().lock())?;
    let Some((dump, output)) = paths else {
        println!("Análise cancelada.");
        return Ok(());
    };
    println!("\nAnalisando o dump. Saída em {}", display_path(&output));
    analyze_dump(&dump, &output, Options::full(), false, true)
}

fn choose_paths(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    writeln!(output, "PS5 Zstd TOML Generator\n")?;
    let (dump, root) = loop {
        let Some(path) = prompt(input, output, "Caminho da pasta do dump extraído")? else {
            return Ok(None);
        };
        let dump = PathBuf::from(path);
        match dump_root(&dump) {
            Ok(root) => break (dump, root),
            Err(error) => writeln!(output, "Pasta do dump inválida. {error}")?,
        }
    };

    let suggested = match suggest_output(&root) {
        Ok(suggested) => suggested,
        Err(error) => {
            writeln!(output, "Escolha outra pasta para a saída. {error}")?;
            None
        }
    };
    let question = match &suggested {
        Some(path) => format!(
            "Pasta nova para a saída [Enter para {}]",
            display_path(path)
        ),
        None => "Caminho de uma pasta nova fora do dump".into(),
    };
    loop {
        let Some(path) = prompt(input, output, &question)? else {
            return Ok(None);
        };
        let destination = if path.is_empty() {
            let Some(path) = &suggested else {
                writeln!(output, "Informe um caminho para a saída.")?;
                continue;
            };
            path.clone()
        } else {
            PathBuf::from(path)
        };
        match check_output(&root, &destination) {
            Ok(path) => return Ok(Some((dump, path))),
            Err(error) => writeln!(output, "Pasta de saída inválida. {error}")?,
        }
    }
}

fn prompt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    question: &str,
) -> io::Result<Option<String>> {
    write!(output, "{question}: ")?;
    output.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let path = line.trim();
    Ok(Some(
        path.strip_prefix('"')
            .and_then(|path| path.strip_suffix('"'))
            .unwrap_or(path)
            .to_owned(),
    ))
}

fn dump_root(path: &Path) -> io::Result<PathBuf> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    let is_link = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let is_link = meta.file_type().is_symlink();
    if !meta.is_dir() || is_link {
        return Err(super::argument("Informe o caminho de uma pasta real."));
    }
    path.canonicalize()
}

fn suggest_output(root: &Path) -> io::Result<Option<PathBuf>> {
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        return Ok(None);
    };
    let mut base = name.to_os_string();
    base.push("-toml");
    let first = parent.join(&base);
    if !path_exists(&first)? {
        return Ok(Some(first));
    }
    let mut number = 2;
    loop {
        let mut name = base.clone();
        name.push(format!("-{number}"));
        let next = parent.join(name);
        if !path_exists(&next)? {
            return Ok(Some(next));
        }
        number += 1;
    }
}

fn display_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(local) = path.strip_prefix(r"\\?\") {
            if local.as_bytes().get(1) == Some(&b':') {
                return local.to_owned();
            }
        }
    }
    path.into_owned()
}

pub(crate) fn print_summary(output: &Path, candidates: usize) {
    println!("\nAnálise concluída.");
    println!(
        "Perfil conservador (todos os arquivos soltos): {}",
        display_path(&output.join("profile.toml"))
    );
    println!(
        "Perfil experimental ({candidates} candidatos): {}",
        display_path(&output.join("candidates").join("profile.toml"))
    );
    if candidates == 0 {
        println!("A análise não encontrou candidatos para compressão neste dump.");
    } else {
        println!("Para testar compressão, abra o perfil experimental no Forge em Pack > Custom rules (TOML).");
        println!("Mantenha as listas paths-*.txt ao lado do perfil e valide o resultado no PS5.");
    }
}
