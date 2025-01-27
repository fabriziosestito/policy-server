use kube::CustomResourceExt;
use policy_server::controller::PolicyRevision;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let yaml_output = serde_yaml::to_string(&PolicyRevision::crd()).unwrap();
    let crd_dir = Path::new("config/crd");

    if !crd_dir.exists() {
        fs::create_dir_all(crd_dir).expect("Failed to create config/crd directory");
    }

    let crd_path = crd_dir.join("policyrevision.yaml");
    let mut file = File::create(&crd_path).expect("Failed to create policyrevision.yaml");
    file.write_all(yaml_output.as_bytes())
        .expect("Failed to write CRD YAML");

    println!("CRD written to {:?}", crd_path);
}
