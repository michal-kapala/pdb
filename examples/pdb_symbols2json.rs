use std::{env, fs::File};
use serde::{Serialize, Deserialize};
use chrono;
use serde_json;
use getopts::Options;
use pdb::{FallibleIterator, AddressMap, ImageSectionHeader};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} input.pdb", program);
    print!("{}", opts.usage(&brief));
}

fn print_func(func: &Function) {
    println!("{:#018X}\t\t{}", func.address, func.name);
}

fn add_func_symbol<'a>(symbol: &'a pdb::Symbol<'a>, mapping: &'a mut Vec<Function>, binary_info: &BinaryInfo) -> pdb::Result<Vec<Function>> {
    match symbol.parse()? {
        pdb::SymbolData::Public(data) => {
            // select only public function symbols
            // there can exist public symbols outside of the parsed section headers
            // for instance `__enclave_config` had section index 11 while there were 10 section headers parsed
            if data.function {
                let (section_name, section_offset) = section_info(
                    data.offset.section,
                    binary_info.address_map.original_sections.as_ref()
                );

                let offset_cast: u64 = data.offset.offset.into();

                let f: Function = Function {
                    file: binary_info.file.clone(),
                    section: section_name,
                    // calculate global virtual address
                    address: binary_info.imagebase + section_offset + offset_cast,
                    name: data.name.to_string().into(),
                };
                mapping.push(f.clone());
                print_func(&f);
            };
        }
        pdb::SymbolData::Procedure(data) => {
            let (section_name, section_offset) = section_info(
                data.offset.section,
                binary_info.address_map.original_sections.as_ref()
            );

            let offset_cast: u64 = data.offset.offset.into();

            let f: Function = Function {
                file: binary_info.file.clone(),
                section: section_name,
                // calculate global virtual address
                address: binary_info.imagebase + section_offset + offset_cast,
                name: data.name.to_string().into(),
            };
            mapping.push(f.clone());
            print_func(&f);
        }
        pdb::SymbolData::ManagedProcedure(data) => {
            match data.name {
                None => {},
                Some(name) => {
                    let (section_name, section_offset) = section_info(
                        data.offset.section,
                        binary_info.address_map.original_sections.as_ref()
                    );
        
                    let offset_cast: u64 = data.offset.offset.into();

                    let f: Function = Function {
                        file: binary_info.file.clone(),
                        section: section_name,
                        // calculate global virtual address
                        address: binary_info.imagebase + section_offset + offset_cast,
                        name: name.to_string().into(),
                    };
                    mapping.push(f.clone());
                    print_func(&f);
                }
            }
        }
        _ => {
            // ignore everything else
        }
    }
    //return mapping;
    Ok(mapping.to_vec())
}

struct BinaryInfo<'t> {
    file: String,
    imagebase: u64,
    address_map: AddressMap<'t>
}

impl std::fmt::Display for BinaryInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "File:\t\t\t\t\t{}\nImagebase:\t\t\t\t{:#018x}\nSections:\t\t\t\t{:?}\n", self.file, self.imagebase, self.address_map.original_sections)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Function {
    file: String,
    section: String,
    address: u64,
    name: String,
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.address, self.name)
    }
}

fn walk_symbols<'a>(mut symbols: pdb::SymbolIter<'a>, mapping: &'a mut Vec<Function>, binary_info: &BinaryInfo) -> pdb::Result<Vec<Function>> {
    let mut result: Result<Vec<Function>, pdb::Error> = Ok(Vec::new());
    while let Some(symbol) = symbols.next()? {
        result = add_func_symbol(&symbol, mapping, binary_info);
        match result {
            Ok(_) => (),
            Err(_) => (),
        }
    }
    result
}

/// Returns section name and offset by its index.
fn section_info(section_index: u16, sections: &Vec<ImageSectionHeader>) -> (String, u64) {
    let index = usize::from(section_index - 1);

    // missing section reference
    if section_index == 0 || usize::from(section_index) > sections.len() {
        return ("".to_string(), 0);
    }
    
    let section = sections[index];
    return (section.name().to_string(), section.virtual_address.into());
}

fn dump_pdb(filename: &str, imagebase: u64) -> pdb::Result<()> {
    let file = std::fs::File::open(filename)?;
    let mut pdb = pdb::PDB::open(file)?;
    let address_map = pdb.address_map()?;
    let symbol_table = pdb.global_symbols()?;
    let binary_info = BinaryInfo {
        file: filename.to_string(),
        imagebase,
        address_map,
    };
    print!("{}", binary_info);

    // save function-address mappings to a JSON file
    let mut mapping: Vec<Function> = Vec::new();
    
    println!("Global symbols:");
    walk_symbols(symbol_table.iter(), &mut mapping, &binary_info)?;
    println!("Global functions found: {}", mapping.len());

    println!("Module private symbols:");
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    while let Some(module) = modules.next()? {
        println!("Module: {}", module.object_file_name());
        let info = match pdb.module_info(&module)? {
            Some(info) => info,
            None => {
                println!("no module info");
                continue;
            }
        };
        walk_symbols(info.symbols()?, &mut mapping, &binary_info)?;
    }
    println!("All functions found: {}", mapping.len());
    serde_json::to_writer(File::create(format!("{filename}.json")).unwrap(), &mapping).unwrap();
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("i", "imagebase", "Hexadecimal `ImageBase` of the corresponding PE binary.", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };

    let imagebase_str = match matches.opt_str("imagebase") {
        Some(addr) => {
            addr
        },
        None => "0".to_string(),
    };

    if imagebase_str == "0".to_string() {
        println!("imagebase not supplied, defaulting to RVAs");
    };

    let parse_result = u64::from_str_radix(&imagebase_str, 16);
    let imagebase = match parse_result {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("error parsing imagebase, defaulting to RVAs:\n{}", e);
            0
        },
    };

    let filename = if matches.free.len() == 1 {
        &matches.free[0]
    } else {
        print_usage(&program, opts);
        return;
    };

    println!("Execution started:\t\t{}", chrono::offset::Local::now());
    match dump_pdb(filename, imagebase) {
        Ok(_) => (),
        Err(e) => eprintln!("error dumping PDB: {}", e),
    }
    println!("Execution finished:\t\t{}", chrono::offset::Local::now());
}
