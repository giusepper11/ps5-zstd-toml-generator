use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::{analyze_dump, check_output, path_exists, Options};

pub(crate) fn run() -> io::Result<()> {
    let paths = choose_paths(&mut io::stdin().lock(), &mut io::stdout().lock())?;
    let Some((dump, output)) = paths else {
        println!("Analysis canceled.");
        return Ok(());
    };
    println!(
        "\nAnalyzing the dump. Output folder: {}",
        display_path(&output)
    );
    analyze_dump(&dump, &output, Options::full(), false, true)
}

fn choose_paths(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    writeln!(output, "PS5 Zstd TOML Generator\n")?;
    let (dump, root) = loop {
        let Some(path) = prompt(input, output, "Path to the extracted dump folder")? else {
            return Ok(None);
        };
        let dump = PathBuf::from(path);
        match dump_root(&dump) {
            Ok(root) => break (dump, root),
            Err(error) => writeln!(output, "Invalid dump folder. {error}")?,
        }
    };

    let suggested = match suggest_output(&root) {
        Ok(suggested) => suggested,
        Err(error) => {
            writeln!(output, "Choose a different output folder. {error}")?;
            None
        }
    };
    let question = match &suggested {
        Some(path) => format!("New output folder [press Enter for {}]", display_path(path)),
        None => "Path to a new folder outside the dump".into(),
    };
    loop {
        let Some(path) = prompt(input, output, &question)? else {
            return Ok(None);
        };
        let destination = if path.is_empty() {
            let Some(path) = &suggested else {
                writeln!(output, "Enter a path for the output folder.")?;
                continue;
            };
            path.clone()
        } else {
            PathBuf::from(path)
        };
        match check_output(&root, &destination) {
            Ok(path) => return Ok(Some((dump, path))),
            Err(error) => writeln!(output, "Invalid output folder. {error}")?,
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

pub(crate) fn confirm_frostbite(count: usize) -> io::Result<bool> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "\nFrostbite game archives with potential space savings: {count}."
    )?;
    writeln!(
        output,
        "Test gameplay on a PS5 before relying on compression for these archives."
    )?;
    loop {
        let Some(answer) = prompt(
            &mut input,
            &mut output,
            "Include these archives in the test profile? [y/N]",
        )?
        else {
            return Ok(false);
        };
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => return Ok(false),
            _ => writeln!(
                output,
                "Enter Y for yes or press Enter to keep the archives loose."
            )?,
        }
    }
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
        return Err(super::argument("Choose a folder that is not a link."));
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
    println!("\nAnalysis complete.");
    if candidates == 0 {
        println!("No compression profile was generated.");
        println!(
            "Analysis report: {}",
            display_path(&output.join("report.txt"))
        );
    } else {
        println!(
            "Experimental profile ({candidates} candidates): {}",
            display_path(&output.join("profile.toml"))
        );
        println!(
            "Open this profile under Pack > Custom rules (TOML) in Forge to test compression."
        );
        println!(
            "Keep any paths-*.txt files next to the profile and validate the result on a PS5."
        );
    }
}
