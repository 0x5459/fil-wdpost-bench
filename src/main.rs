use std::{env, fs::File, path::PathBuf, sync::Arc};

use anyhow::{ensure, Result};
use bellperson::groth16;
use blstrs::Bls12;
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    as_safe_commitment,
    caches::lookup_groth_params,
    parameters::{window_post_public_params, window_post_setup_params},
    ChallengeSeed, MerkleTreeTrait, PoStConfig, PoStType, ProverId, SectorShape32GiB,
};
use filecoin_proofs_api::RegisteredPoStProof;
use rand::rngs::OsRng;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    parameter_cache::Bls12GrothParams,
};
use storage_proofs_post::fallback::{
    self, FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound, PublicSector,
};

fn main() {
    env_logger::init();

    let randomness = [
        156, 40, 35, 233, 178, 130, 183, 47, 22, 168, 5, 55, 185, 78, 43, 202, 117, 156, 69, 3,
        209, 71, 39, 214, 191, 3, 252, 245, 150, 175, 208, 50,
    ];
    let prover_id = [
        200, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    let post_config = RegisteredPoStProof::StackedDrgWindow32GiBV1_2.as_v1_config();
    let snark_proof = window_post::<SectorShape32GiB>(
        &post_config,
        &randomness,
        prover_id,
        load_sectors::<SectorShape32GiB>(),
        load_vanilla::<SectorShape32GiB>(),
    )
    .unwrap();
    dbg!(snark_proof);
}

fn load_vanilla<Tree: MerkleTreeTrait>() -> Vec<filecoin_proofs::types::VanillaProof<Tree>> {
    let path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("vanilla.bin");
    bincode::deserialize_from(File::open(path).unwrap()).unwrap()
}

fn load_sectors<Tree: MerkleTreeTrait>() -> Vec<PublicSector<<Tree::Hasher as Hasher>::Domain>> {
    let path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("pub_sectors.bin");
    bincode::deserialize_from(File::open(path).unwrap()).unwrap()
}

fn window_post<Tree: MerkleTreeTrait + 'static>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    pub_sectors: Vec<PublicSector<<Tree::Hasher as Hasher>::Domain>>,
    vanilla_proofs: Vec<filecoin_proofs::types::VanillaProof<Tree>>,
) -> Result<Vec<groth16::Proof<Bls12>>> {
    let randomness_safe = as_safe_commitment(&randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(pub_sectors.len(), post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(post_config)?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        vanilla_proofs,
        &groth_params,
    )
}

pub(crate) fn get_post_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12GrothParams>> {
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let post_public_params = window_post_public_params::<Tree>(post_config)?;

    let parameters_generator = || {
        <FallbackPoStCompound<Tree> as CompoundProof<
            FallbackPoSt<'_, Tree>,
            FallbackPoStCircuit<Tree>,
        >>::groth_params::<OsRng>(None, &post_public_params)
        .map_err(Into::into)
    };

    Ok(lookup_groth_params(
        format!(
            "Window_POST[{}]",
            usize::from(post_config.padded_sector_size())
        ),
        parameters_generator,
    )?)
}

pub(crate) fn get_partitions_for_window_post(
    total_sector_count: usize,
    post_config: &PoStConfig,
) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}
