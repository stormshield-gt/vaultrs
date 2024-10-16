use std::{borrow::Cow, collections::HashMap, fs, mem};

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use testcontainers::{
    core::{AccessMode, ContainerState, ExecCommand, Mount, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, Image, ImageExt, TestcontainersError,
};
use testcontainers_modules::{localstack::LocalStack, postgres::Postgres};

use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

pub struct Test<I>
where
    I: Image,
{
    client: VaultClient,
    /// Vault handle, remove the container on drop.
    _vault: ContainerAsync<I>,

    /// For aws tests.
    localstack: Option<RunningLocalStack>,
    postgres: Option<RunningPostgres>,
}

impl<T> Test<T>
where
    T: Image,
{
    pub fn client(&self) -> &VaultClient {
        &self.client
    }

    pub fn localstack_url(&self) -> Option<&str> {
        self.localstack
            .as_ref()
            .map(|localstack| localstack.url.as_str())
    }

    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres.as_ref().map(|postgres| postgres.url.as_str())
    }
}

impl Test<Vault> {
    pub async fn new() -> Self {
        let (client, vault) = Self::new_vault().await;

        Self {
            client,
            _vault: vault,
            localstack: None,
            postgres: None,
        }
    }

    async fn new_vault() -> (VaultClient, ContainerAsync<Vault>) {
        let vault = Vault::default()
            .start()
            .await
            .expect("vault should have started");

        let host_port = vault
            .get_host_port_ipv4(8200)
            .await
            .expect("host port shoudl be mapped");
        let addr = format!("http://localhost:{host_port}");

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(addr)
                .token("root")
                .build()
                .unwrap(),
        )
        .unwrap();
        let _ = tracing_subscriber::FmtSubscriber::builder()
            .with_test_writer()
            .try_init();
        (client, vault)
    }

    pub async fn new_with_localstack(
        services: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        // TODO: when Iterator::intersperse is stable use it.
        // https://docs.localstack.cloud/references/configuration//
        let mut services_env = String::new();
        for service in services {
            let service: String = service.into();
            services_env.push_str(&service);
            services_env.push(',');
        }
        let services_env = services_env.strip_suffix(',').unwrap();
        let localstack = LocalStack::default()
            .with_env_var("SERVICES", services_env)
            .start()
            .await
            .unwrap();
        let bridge_ip = localstack.get_bridge_ip_address().await.unwrap();
        let url = format!("http://{bridge_ip}:4566");
        let (client, vault) = Self::new_vault().await;
        Self {
            client,
            _vault: vault,
            localstack: Some(RunningLocalStack {
                _localstack: localstack,
                url,
            }),
            postgres: None,
        }
    }

    pub async fn new_with_postgres() -> Self {
        let postgres = Postgres::default()
            .with_user(POSTGRES_USER)
            .with_password(POSTGRES_PASSWORD)
            .start()
            .await
            .unwrap();
        let bridge_ip = postgres.get_bridge_ip_address().await.unwrap();
        let url = format!("{bridge_ip}:5432");
        let (client, vault) = Self::new_vault().await;
        Self {
            client,
            _vault: vault,
            localstack: None,
            postgres: Some(RunningPostgres {
                _postgres: postgres,
                url,
            }),
        }
    }
}

impl Test<TlsVault> {
    pub async fn new_tls() -> Self {
        let vault = TlsVault::default()
            .start()
            .await
            .expect("vault should have started");

        let host_port = vault
            .get_host_port_ipv4(8200)
            .await
            .expect("host port shoudl be mapped");
        let addr = format!("https://localhost:{host_port}");

        let identity = reqwest::Identity::from_pem(
            fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/files/tls/vault_client.pem"
            ))
            .unwrap()
            .as_bytes(),
        )
        .unwrap();

        let ca_cert =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/tls/ca_cert.crt").to_string();

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(addr)
                .token("root")
                .identity(Some(identity))
                .ca_certs(vec![ca_cert])
                .build()
                .unwrap(),
        )
        .unwrap();

        Self {
            client,
            _vault: vault,
            localstack: None,
            postgres: None,
        }
    }
}

impl Test<ProdVault> {
    pub async fn new_prod() -> Self {
        let (client, vault) = Self::new_vault_prod().await;

        Self {
            client,
            _vault: vault,
            localstack: None,
            postgres: None,
        }
    }

    async fn new_vault_prod() -> (VaultClient, ContainerAsync<ProdVault>) {
        let vault = ProdVault::default()
            .start()
            .await
            .expect("vault should have started");

        let host_port = vault
            .get_host_port_ipv4(8200)
            .await
            .expect("host port shoudl be mapped");
        let addr = format!("http://localhost:{host_port}");

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(addr)
                .build()
                .unwrap(),
        )
        .unwrap();
        let _ = tracing_subscriber::FmtSubscriber::builder()
            .with_test_writer()
            .try_init();
        (client, vault)
    }
}

pub struct Vault {
    env_vars: HashMap<String, String>,
    volumes: Vec<Mount>,
}

impl Default for Vault {
    fn default() -> Self {
        // We configure environment variable inside the docker so we can make the healthcheck through the CLI.
        Self {
            env_vars: HashMap::from([("VAULT_DEV_ROOT_TOKEN_ID".to_owned(), "root".to_owned())]),
            volumes: Vec::new(),
        }
    }
}

impl Image for Vault {
    fn name(&self) -> &str {
        NAME
    }

    fn tag(&self) -> &str {
        TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        // The wait condition is in `exec_after_start`.
        vec![WaitFor::Nothing]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        Box::new(self.env_vars.iter())
    }

    fn exec_after_start(
        &self,
        _cs: ContainerState,
    ) -> Result<Vec<ExecCommand>, TestcontainersError> {
        // We block until the vault server healthcheck pass.
        // TODO: When `WaitForHttp` is implemented, we can use it like in the Go implementation:
        // https://github.com/testcontainers/testcontainers-go/blob/91f6f595bf553af948b8a57234dac00ff8e63dc3/modules/vault/vault.go#L32
        // https://github.com/testcontainers/testcontainers-rs/issues/648
        Ok(vec![ExecCommand::new([String::from(
            "until vault status | awk 'NR == 5 { print $2 }' | \
                 grep -x true; do echo \"Try again\"; done",
        )])
        .with_container_ready_conditions(vec![
            WaitFor::message_on_stdout("true"),
        ])])
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        Box::new(self.volumes.iter())
    }
}

pub struct TlsVault {
    env_vars: HashMap<String, String>,
    volumes: Vec<Mount>,
}

impl Default for TlsVault {
    fn default() -> Self {
        // We configure environment variable inside the docker so we can make the healthcheck through the CLI.
        Self {
            env_vars: HashMap::from([
                ("VAULT_DEV_ROOT_TOKEN_ID".to_owned(), "root".to_owned()),
                ("VAULT_ADDR".to_owned(), "https://localhost:8200".to_owned()),
                (
                    "VAULT_CACERT".to_owned(),
                    "/vault/config/ca_cert.crt".to_owned(),
                ),
                // Setting 9999 to leave 8200 available for the listener configured config.hcl
                (
                    "VAULT_DEV_LISTEN_ADDRESS".to_owned(),
                    "0.0.0.0:9999".to_owned(),
                ),
            ]),
            volumes: vec![Mount::bind_mount(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/tls"),
                "/vault/config",
            )
            .with_access_mode(AccessMode::ReadOnly)],
        }
    }
}

impl Image for TlsVault {
    fn name(&self) -> &str {
        NAME
    }

    fn tag(&self) -> &str {
        TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        // The wait condition is in `exec_after_start`.
        vec![WaitFor::Nothing]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        Box::new(self.env_vars.iter())
    }

    fn exec_after_start(
        &self,
        _cs: ContainerState,
    ) -> Result<Vec<ExecCommand>, TestcontainersError> {
        // We block until the vault server healthcheck pass.
        // TODO: When `WaitForHttp` is implemented, we can use it like in the Go implementation:
        // https://github.com/testcontainers/testcontainers-go/blob/91f6f595bf553af948b8a57234dac00ff8e63dc3/modules/vault/vault.go#L32
        // https://github.com/testcontainers/testcontainers-rs/issues/648
        Ok(vec![ExecCommand::new([String::from(
            "until vault status | awk 'NR == 5 { print $2 }' | \
                 grep -x true; do echo \"Try again\"; done",
        )])
        .with_container_ready_conditions(vec![
            WaitFor::message_on_stdout("true"),
        ])])
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        Box::new(self.volumes.iter())
    }

    // fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
    //     // By default the Vault server will read the config file inside `/vault/config`
    //     vec!["server"].into_iter()
    // }
}

/// A vault that is not in a dev mod.
/// Can be useful to test unseal and initialization workflows.
pub struct ProdVault {
    env_vars: HashMap<String, String>,
    volumes: Vec<Mount>,
}

impl Default for ProdVault {
    fn default() -> Self {
        Self {
            env_vars: HashMap::from([(
                "VAULT_LOCAL_CONFIG".to_owned(),
                serde_json::json!({
                    "listener": [
                        {
                            "tcp": {
                                "address": "0.0.0.0:8200",
                                "tls_disable": "true"
                            }
                        }
                    ],
                    "storage": [
                        {
                            "inmem": {}
                        }
                    ],
                    "disable_mlock": true

                })
                .to_string(),
            )]),
            volumes: Vec::new(),
        }
    }
}

impl Image for ProdVault {
    fn name(&self) -> &str {
        NAME
    }

    fn tag(&self) -> &str {
        TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        // The wait condition is in `exec_after_start`.
        vec![WaitFor::Nothing]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        Box::new(self.env_vars.iter())
    }

    fn exec_after_start(
        &self,
        _cs: ContainerState,
    ) -> Result<Vec<ExecCommand>, TestcontainersError> {
        // We block until the vault server healthcheck pass.
        // TODO: When `WaitForHttp` is implemented, we can use it like in the Go implementation:
        // https://github.com/testcontainers/testcontainers-go/blob/91f6f595bf553af948b8a57234dac00ff8e63dc3/modules/vault/vault.go#L32
        // https://github.com/testcontainers/testcontainers-rs/issues/648
        Ok(vec![ExecCommand::new([String::from(
            "until vault status | awk 'NR == 5 { print $2 }' | \
                 grep -x true; do echo \"Try again\"; done",
        )])
        .with_container_ready_conditions(vec![
            WaitFor::message_on_stdout("true"),
        ])])
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        Box::new(self.volumes.iter())
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        // By default the Vault server will read the config file inside `/vault/config`
        vec!["server"].into_iter()
    }
}

pub const POSTGRES_USER: &str = "postgres";
pub const POSTGRES_PASSWORD: &str = "postgres";

const NAME: &str = "hashicorp/vault";
const TAG: &str = "1.10.3";

struct RunningLocalStack {
    /// Localstack handle, remove the container on drop.
    _localstack: ContainerAsync<LocalStack>,
    url: String,
}

struct RunningPostgres {
    /// Postgres handle, remove the container on drop.
    _postgres: ContainerAsync<Postgres>,
    url: String,
}

pub fn generate_certs() -> Certificates {
    let mut ca_cert_params = CertificateParams::new([]);
    ca_cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_cert_params).unwrap();

    let client_cert_params = CertificateParams::new([]);
    let client_cert = Certificate::from_params(client_cert_params).unwrap();

    let server_cert_params = CertificateParams::new(["localhost".to_string()]);
    let server_cert = Certificate::from_params(server_cert_params).unwrap();

    // We need to serialize the ca and server certs so that we can mount them within the vault container
    let serialized_cert_dir = tempfile::tempdir().unwrap();
    eprintln!("{:?}", serialized_cert_dir.path());

    let ca_cert_path = serialized_cert_dir.path().to_path_buf().join("ca_cert.crt");
    fs::write(ca_cert_path, ca_cert.serialize_pem().unwrap()).unwrap();

    let server_cert_path = serialized_cert_dir
        .path()
        .to_path_buf()
        .join("vault_server.crt");
    fs::write(
        server_cert_path,
        server_cert.serialize_pem_with_signer(&ca_cert).unwrap(),
    )
    .unwrap();

    let server_key_path = serialized_cert_dir
        .path()
        .to_path_buf()
        .join("vault_server.key");
    fs::write(server_key_path, server_cert.serialize_private_key_pem()).unwrap();

    let mut pem = client_cert
        .serialize_pem_with_signer(&ca_cert)
        .unwrap()
        .into_bytes();

    let mut client_key = client_cert.serialize_private_key_pem().as_bytes().to_vec();
    pem.append(&mut client_key);

    let vault_client = serialized_cert_dir
        .path()
        .to_path_buf()
        .join("vault_client.pem");
    fs::write(vault_client, pem).unwrap();

    mem::forget(serialized_cert_dir);

    Certificates {
        ca_cert,
        // client_cert,
        // serialized_cert_dir,
    }
}

pub struct Certificates {
    ca_cert: Certificate,
    // client_cert: Certificate,
}
