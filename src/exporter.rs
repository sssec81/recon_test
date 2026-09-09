use crate::diff::ScanDiffResult;
use crate::models::HttpObservation;
use std::fs::File;
use std::io::Write;

pub fn export_json(observations: &[HttpObservation], file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json_data = serde_json::to_string_pretty(observations)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}

pub fn export_csv(observations: &[HttpObservation], file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(file_path)?;
    for obs in observations {
        writer.serialize(obs)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn export_diff_json(diff: &ScanDiffResult, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json_data = serde_json::to_string_pretty(diff)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}
