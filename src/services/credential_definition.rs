use std::sync::Mutex;

use crate::error::*;
use crate::storage::in_memory::ObjectCache;
use aries_vcx::indy::primitives::credential_definition::{CredentialDef, CredentialDefConfig};
use aries_vcx::vdrtools_sys::{PoolHandle, WalletHandle};

pub struct ServiceCredentialDefinitions {
    wallet_handle: WalletHandle,
    pool_handle: PoolHandle,
    cred_defs: ObjectCache<CredentialDef>,
}

impl ServiceCredentialDefinitions {
    pub fn new(wallet_handle: WalletHandle, pool_handle: PoolHandle) -> Self {
        Self {
            wallet_handle,
            pool_handle,
            cred_defs: ObjectCache::new("cred-defs"),
        }
    }

    pub async fn create_cred_def(&self, config: CredentialDefConfig) -> AgentResult<String> {
        let cd = CredentialDef::create(
            self.wallet_handle,
            self.pool_handle,
            "".to_string(),
            config,
            true,
        )
        .await?;
        self.cred_defs.add(&cd.get_cred_def_id(), cd)
    }

    pub async fn publish_cred_def(&self, id: &str) -> AgentResult<()> {
        let cred_def = self.cred_defs.get_cloned(id)?;
        let cred_def = cred_def
            .publish_cred_def(self.wallet_handle, self.pool_handle)
            .await?;
        self.cred_defs.add(id, cred_def)?;
        Ok(())
    }

    pub fn cred_def_json(&self, id: &str) -> AgentResult<String> {
        self.cred_defs
            .get_cloned(id)?
            .get_data_json()
            .map_err(|err| err.into())
    }

    pub fn find_by_schema_id(&self, schema_id: &str) -> AgentResult<Vec<String>> {
        let schema_id = schema_id.to_string();
        let f = |(id, m): (&String, &Mutex<CredentialDef>)| -> Option<String> {
            let cred_def = m.lock().unwrap();
            if cred_def.get_schema_id() == schema_id {
                Some(id.clone())
            } else {
                None
            }
        };
        self.cred_defs.find_by(f)
    }
}
