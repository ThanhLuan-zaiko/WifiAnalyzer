use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use wifi_core::{normalize_records, recommend_channels, ScanRecord};

#[pyfunction]
fn normalize_records_json(records_json: &str) -> PyResult<String> {
    let mut records: Vec<ScanRecord> = serde_json::from_str(records_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    normalize_records(&mut records);
    serde_json::to_string(&records).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn recommend_channels_json(records_json: &str, band: &str, top_n: usize) -> PyResult<String> {
    let mut records: Vec<ScanRecord> = serde_json::from_str(records_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    normalize_records(&mut records);
    let recommendations = recommend_channels(&records, band, top_n);
    serde_json::to_string(&recommendations)
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
fn wifi_backend(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_records_json, m)?)?;
    m.add_function(wrap_pyfunction!(recommend_channels_json, m)?)?;
    Ok(())
}
