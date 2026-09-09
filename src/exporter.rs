use crate::models::Target;
use std::fs::File;
use std::io::Write;

pub fn export_json(targets: &[Target], file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json_data = serde_json::to_string_pretty(targets)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

pub fn export_csv(targets: &[Target], file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(file_path)?;
    for target in targets {
        writer.serialize(target)?;
    }
    writer.flush()?;
    Ok(())
}
