# PS5 Zstd TOML Generator

Biblioteca Rust e CLI para gerar perfis TOML de empacotamento AMPR Zstd a partir de um dump de PS5 em formato de pasta. O executável se chama `ps5-pack-analyzer`. Ele lê o dump localmente, gera relatórios e perfis para o PS5 Dump Forge e deixa o empacotamento a cargo do Forge.

**O perfil padrão mantém todos os arquivos soltos.** O perfil em `candidates/` propõe arquivos para compressão com base em evidência estática e, no modo completo, em amostras de economia. A seleção depende do dump analisado e precisa de validação em console.

## Início rápido no Windows x64

1. Abra [Releases](https://github.com/giusepper11/ps5-zstd-toml-generator/releases), selecione a pré-release e baixe o ZIP `windows-x64` da seção **Assets**.
2. Extraia o ZIP inteiro e abra `Abrir-gerador.cmd` com dois cliques. A versão portátil roda sem Rust ou Git.
3. Cole o caminho da pasta do dump extraído. Pressione Enter para usar a pasta de saída sugerida ou informe outra pasta nova. O assistente mostra os caminhos dos perfis ao terminar.

`profile.toml` mantém todos os arquivos soltos. Se houver candidatos, abra `candidates/profile.toml` em **Pack → Custom rules (TOML)** no Forge para testar compressão. Mantenha as listas `paths-*.txt` ao lado do perfil e valide o resultado no PS5.

A pré-release sai sem assinatura de código e o Windows pode exibir um aviso de reputação. Compare o SHA-256 do ZIP com o arquivo `.sha256` da mesma pré-release. No PowerShell, você também pode chamar o executável diretamente.

```powershell
.\ps5-pack-analyzer.exe 'D:\Meu Jogo' 'D:\Meu Jogo-toml'
.\ps5-pack-analyzer.exe --verify 'D:\Meu Jogo' 'D:\Meu Jogo-toml'
```

## Compilar a partir do código-fonte

Requer Rust 1.85 ou posterior e um dump extraído em formato de pasta, com caminhos UTF-8. Os comandos abaixo usam caminhos de exemplo relativos à raiz do repositório. `saida` deve ser um diretório novo fora do dump, com diretório pai existente. Mantenha o dump estático durante a análise.

```sh
git clone https://github.com/giusepper11/ps5-zstd-toml-generator.git
cd ps5-zstd-toml-generator
cargo run --release --locked -- ./meu-dump ./saida
```

O modo padrão `--full` inventaria a árvore, examina cabeçalhos e executáveis legíveis e mede amostras de compressão das famílias candidatas. `--strict` restringe os candidatos aos argumentos aparentes do resolvedor APR. `--manifest-candidates` inclui hipóteses de catálogos. `--headers` amplia a inspeção de cabeçalhos em qualquer um desses dois modos. Rode com `--help` para ver a lista de opções.

| Arquivo | Conteúdo |
| --- | --- |
| `profile.toml` | Perfil conservador com `default_action = "loose"` |
| `candidates/profile.toml` | Perfil experimental com a seleção sugerida |
| `paths-*.txt` | Listas opcionais de padrões. Mantenha-as ao lado do perfil que as referencia |
| `selected.txt` | Caminhos selecionados no perfil da mesma pasta |
| `certificate.txt` | Hashes do inventário, perfil, seleção e intervalos de evidência |
| `report.txt` e `decisions.tsv` | Cobertura, decisões por arquivo e motivos |

Use `--exploratory` para exportar os candidatos também em `profile.toml`. Para testar um perfil no Forge, use **Custom rules (TOML)** na aba **Pack** ou `--pack-profile` na CLI do Forge. Perfis são aplicados na próxima geração do pack. A saída do analisador tem limite de 256 MiB, e no Windows a CLI exige também 1 GiB de espaço livre de reserva.

O modelo de seleção acompanha o [PS5 Dump Forge 0.5.4](https://github.com/quer3q/ps5-dump-forge/blob/v0.5.4/docs/packing.md) e o [ampr-emu-ng 0.3.2](https://github.com/quer3q/ampr-emu-ng/blob/v0.3.2/docs/zstd-format.md). Confirme as versões que você usa antes de aplicar o perfil. Para validar candidatos, exercite no console o boot a frio, carregamento de saves, áudio, idiomas, streaming e transições relevantes à versão do jogo.

## Verificar um resultado

```sh
cargo run --release --locked -- --verify ./meu-dump ./saida
cargo run --release --locked -- --verify ./meu-dump ./saida/candidates
cargo run --release --locked -- --trace ./trace.tsv ./saida/certificate.txt
```

`--verify` confere a seleção e o perfil contra o inventário e relê os intervalos registrados em blocos de até 4 MiB. Por padrão, o certificado cobre as faixas lidas durante a análise. Use `--full-hash` durante a geração para registrar todos os bytes, com custo proporcional ao tamanho do dump. O certificado é uma verificação de integridade, sem autenticação de origem ou garantia de snapshot atômico. A geração exige ao menos uma faixa de evidência não vazia.

`--trace` lê um arquivo gerado por um gravador externo e confere o hash do texto do certificado. O [formato TSV](trace-schema.md) descreve como registrar as observações. O relatório cobre os cenários exercitados e a identidade informada pelo gravador.

Os relatórios, listas, traces e certificados podem conter caminhos e metadados do dump. Use resultados sintéticos quando compartilhar um exemplo público.

## Biblioteca e desenvolvimento

- `SourceTree` permite fornecer um inventário estável e leituras exatas por intervalo. `FolderSource` é o adaptador da CLI.
- `analyze` e `analyze_with_progress` retornam `Analysis`, com acesso separado ao perfil principal e aos candidatos.
- `forge::verify_generated` confere o subconjunto de TOML emitido pelo gerador. `forge::verify_with_selector` permite ao host conferir o perfil com o seletor real do Forge.
- A [API de economia e o amostrador opcional para Node.js 24](ECONOMICS.md) descrevem a medição por blocos e seus limites.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
node scripts/sample-zstd.mjs --self-test
```

Os testes Rust criam entradas sintéticas e podem rodar sem arquivos de jogos. Para estimar economia, o gerador envia blocos brutos à API de compressão do `ruzstd`. O leitor de catálogos XML limita cada elemento a 128 atributos.

## Licença

[MIT](LICENSE).
