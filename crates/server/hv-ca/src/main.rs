//! hv-ca: internal certificate authority. Issues per-host client certificates
//! in exchange for a one-time enrolment token, renews them, and keeps a
//! revocation list hv-ingest consults on connect. Private key stays on disk
//! with 0600 permissions; HSM/PKCS#11 is a v1.x option.

use anyhow::Result;
use hv_proto::{
    enrolment_server::{Enrolment, EnrolmentServer},
    Config as AgentCfg, EnrolRequest, EnrolResponse, RenewRequest,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType,
    IsCa, KeyPair, KeyUsagePurpose,
};
use sqlx::PgPool;
use tonic::{transport::Server, Request, Response, Status};

pub struct Ca {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_der: Vec<u8>,
    pg: PgPool,
}

impl Ca {
    pub fn load_or_create(dir: &std::path::Path) -> Result<(Certificate, KeyPair, Vec<u8>)> {
        std::fs::create_dir_all(dir)?;
        let kp = dir.join("ca.key");
        let cp = dir.join("ca.pem");
        if kp.exists() && cp.exists() {
            let key = KeyPair::from_pem(&std::fs::read_to_string(&kp)?)?;
            let params = CertificateParams::from_ca_cert_pem(&std::fs::read_to_string(&cp)?)?;
            let cert = params.self_signed(&key)?;
            let der = cert.der().to_vec();
            return Ok((cert, key, der));
        }
        let mut p = CertificateParams::new(vec![])?;
        p.distinguished_name
            .push(DnType::CommonName, "HostVigil Internal CA");
        p.distinguished_name
            .push(DnType::OrganizationName, "HostVigil");
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        p.not_after = rcgen::date_time_ymd(2036, 1, 1);
        let key = KeyPair::generate()?;
        let cert = p.self_signed(&key)?;
        std::fs::write(&kp, key.serialize_pem())?;
        std::fs::write(&cp, cert.pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::warn!(fingerprint = %hv_common::sha256_hex(cert.pem().as_bytes()), "new CA created; distribute this fingerprint with the agent installer");
        let der = cert.der().to_vec();
        Ok((cert, key, der))
    }

    async fn issue(&self, csr_der: &[u8], host_id: &str) -> Result<Vec<u8>> {
        let csr_der_owned: rcgen::CertificateSigningRequestDer<'static> = csr_der.to_vec().into();
        let mut csr = CertificateSigningRequestParams::from_der(&csr_der_owned)?;
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(DnType::CommonName, host_id);
        csr.params.not_after = time_in_days(90);
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = csr.signed_by(&self.ca_cert, &self.ca_key)?;
        sqlx::query(
            "INSERT INTO host_certs(host_id, serial, not_after, issued_at) VALUES($1,$2,$3,now())",
        )
        .bind(host_id)
        .bind(hv_common::sha256_hex(cert.der()))
        .bind(time_in_days(90).to_string())
        .execute(&self.pg)
        .await?;
        Ok(cert.der().to_vec())
    }
}

fn time_in_days(d: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::days(d)
}

#[tonic::async_trait]
impl Enrolment for Ca {
    async fn enrol(&self, req: Request<EnrolRequest>) -> Result<Response<EnrolResponse>, Status> {
        let r = req.into_inner();
        let tok: Option<(String, Option<String>)> = sqlx::query_as("UPDATE enrol_tokens SET used_at=now(), used_by=$2 WHERE token=$1 AND used_at IS NULL AND expires_at > now() RETURNING token, group_name").bind(&r.token).bind(r.hello.as_ref().map(|h| h.hostname.clone()).unwrap_or_default()).fetch_optional(&self.pg).await.map_err(|e| Status::internal(e.to_string()))?;
        let Some((_, group)) = tok else {
            tracing::warn!("enrolment with invalid or used token");
            return Err(Status::permission_denied(
                "invalid or expired enrolment token",
            ));
        };
        let hostname = r
            .hello
            .as_ref()
            .map(|h| h.hostname.clone())
            .unwrap_or_else(|| "host".into());
        let host_id = format!(
            "{}-{}",
            hostname.to_lowercase(),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        );
        let cert = self
            .issue(&r.csr_der, &host_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        sqlx::query("INSERT INTO hosts(host_id, hostname, os_version, agent_version, ips, group_name, last_seen, online) VALUES($1,$2,$3,$4,$5,$6,now(),false) ON CONFLICT DO NOTHING").bind(&host_id).bind(&hostname).bind(r.hello.as_ref().map(|h| h.os_version.clone()).unwrap_or_default()).bind(r.hello.as_ref().map(|h| h.agent_version.clone()).unwrap_or_default()).bind(r.hello.as_ref().map(|h| h.ips.clone()).unwrap_or_default()).bind(group).execute(&self.pg).await.map_err(|e| Status::internal(e.to_string()))?;
        tracing::info!(%host_id, %hostname, "enrolled");
        Ok(Response::new(EnrolResponse {
            cert_der: cert,
            ca_der: self.ca_der.clone(),
            host_id,
            config: Some(AgentCfg {
                heartbeat_s: 30,
                inventory_interval_s: 21600,
                ring_buffer_bytes: 2 << 30,
                hash_image_loads: false,
                etw_providers: vec![],
            }),
        }))
    }
    async fn renew(&self, req: Request<RenewRequest>) -> Result<Response<EnrolResponse>, Status> {
        // Renewal is authenticated by the existing client cert (mTLS); CN = host_id.
        let cn: String = {
            let certs = req.peer_certs();
            let der: Option<Vec<u8>> = certs.and_then(|c| c.first().map(|c| c.as_ref().to_vec()));
            der.and_then(|der| {
                x509_parser::parse_x509_certificate(&der)
                    .ok()
                    .and_then(|(_, c)| {
                        c.subject()
                            .iter_common_name()
                            .next()
                            .and_then(|a| a.as_str().ok().map(String::from))
                    })
            })
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?
        };
        let cert = self
            .issue(&req.into_inner().csr_der, &cn)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(EnrolResponse {
            cert_der: cert,
            ca_der: self.ca_der.clone(),
            host_id: cn,
            config: None,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let dir = std::path::PathBuf::from(
        std::env::var("HV_CA_DIR").unwrap_or_else(|_| "/var/lib/hostvigil/ca".into()),
    );
    let (ca_cert, ca_key, ca_der) = Ca::load_or_create(&dir)?;
    let pg = PgPool::connect(
        &std::env::var("HV_POSTGRES_URL")
            .unwrap_or_else(|_| "postgres://hostvigil:hostvigil@postgres/hostvigil".into()),
    )
    .await?;
    let addr = std::env::var("HV_CA_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8444".into())
        .parse()?;
    tracing::info!(%addr, "hv-ca listening");
    Server::builder()
        .add_service(EnrolmentServer::new(Ca {
            ca_cert,
            ca_key,
            ca_der,
            pg,
        }))
        .serve(addr)
        .await?;
    Ok(())
}
