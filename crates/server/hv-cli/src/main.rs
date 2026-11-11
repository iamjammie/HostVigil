//! hv-cli: operator tasks that should not need the HUD.
use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::PgPool;

#[derive(Parser)]
#[command(name = "hv", about = "HostVigil server CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(
        long,
        env = "HV_POSTGRES_URL",
        default_value = "postgres://hostvigil:hostvigil@localhost/hostvigil"
    )]
    pg: String,
}
#[derive(Subcommand)]
enum Cmd {
    /// Create an enrolment token (default 24h, single use).
    Token {
        #[arg(long)]
        group: Option<String>,
        #[arg(long, default_value_t = 24)]
        hours: i64,
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// Create or reset a HUD user.
    User {
        username: String,
        #[arg(long, default_value = "viewer")]
        role: String,
        #[arg(long)]
        password: String,
    },
    /// Generate the Ed25519 key pair used to sign commands and feed bundles.
    Keygen {
        #[arg(long, default_value = "/var/lib/hostvigil/keys")]
        dir: String,
    },
    /// Revoke a host certificate and mark the host decommissioned.
    Revoke { host_id: String },
    /// Print fleet summary.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::Keygen { dir } = &cli.cmd {
        {
            use ed25519_dalek::SigningKey;
            use rand_core::OsRng;
            std::fs::create_dir_all(dir)?;
            let sk = SigningKey::generate(&mut OsRng);
            std::fs::write(format!("{dir}/command.key"), hv_common::hex(&sk.to_bytes()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    format!("{dir}/command.key"),
                    std::fs::Permissions::from_mode(0o600),
                )?;
            }
            println!(
                "public key (put in agent.toml command_pubkey and HV_FEED_PUBKEY):\n{}",
                hv_common::hex(sk.verifying_key().as_bytes())
            );
            return Ok(());
        }
    }
    let pg = PgPool::connect(&cli.pg).await?;
    match cli.cmd {
        Cmd::Token {
            group,
            hours,
            count,
        } => {
            for _ in 0..count {
                let t = uuid::Uuid::new_v4().simple().to_string();
                sqlx::query("INSERT INTO enrol_tokens(token, group_name, expires_at) VALUES($1,$2,now() + make_interval(hours => $3))").bind(&t).bind(&group).bind(hours as i32).execute(&pg).await?;
                println!("{t}");
            }
        }
        Cmd::User {
            username,
            role,
            password,
        } => {
            let hash = {
                use argon2::{
                    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
                    Argon2,
                };
                Argon2::default()
                    .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                    .unwrap()
                    .to_string()
            };
            sqlx::query("INSERT INTO users(username, password_hash, role, enabled) VALUES($1,$2,$3,true) ON CONFLICT(username) DO UPDATE SET password_hash=$2, role=$3").bind(&username).bind(hash).bind(&role).execute(&pg).await?;
            println!("user {username} ({role}) saved");
        }
        Cmd::Revoke { host_id } => {
            sqlx::query("UPDATE host_certs SET revoked_at=now() WHERE host_id=$1")
                .bind(&host_id)
                .execute(&pg)
                .await?;
            sqlx::query("UPDATE hosts SET decommissioned=true, online=false WHERE host_id=$1")
                .bind(&host_id)
                .execute(&pg)
                .await?;
            println!("revoked {host_id}");
        }
        Cmd::Status => {
            let (n, online, avg): (i64, i64, Option<f64>) = sqlx::query_as(
                "SELECT COUNT(*), COUNT(*) FILTER (WHERE online), AVG(posture) FROM hosts",
            )
            .fetch_one(&pg)
            .await?;
            println!(
                "hosts: {n}  online: {online}  avg posture: {:.0}",
                avg.unwrap_or(0.0)
            );
        }
        Cmd::Keygen { .. } => unreachable!(),
    }
    Ok(())
}
