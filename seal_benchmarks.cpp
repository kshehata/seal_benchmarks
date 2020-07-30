#include "benchmark/benchmark.h"

#include <iostream>

#include "seal/seal.h"

using namespace std;
using namespace seal;

constexpr uint32_t POLY_MOD_DEGREE = 4096;
constexpr uint32_t PLAIN_MOD = (1 << 16) + 1;

class SealFixture : public benchmark::Fixture {
 public:
  void SetUp(::benchmark::State& state) {
    EncryptionParameters parms(seal::scheme_type::BFV);
    parms.set_poly_modulus_degree(POLY_MOD_DEGREE);
    parms.set_plain_modulus(PLAIN_MOD);
    parms.set_coeff_modulus(
      seal::CoeffModulus::BFVDefault(POLY_MOD_DEGREE));

    seal_context_ = seal::SEALContext::Create(parms);
    if (!seal_context_->parameters_set()) {
      state.SkipWithError(seal_context_->parameter_error_message());
    }

    keygen_ = make_unique<KeyGenerator>(seal_context_);
    encryptor_ = make_unique<Encryptor>(seal_context_, keygen_->public_key());
    decryptor_ = make_unique<Decryptor>(seal_context_, keygen_->secret_key());
    encoder_ = make_unique<seal::IntegerEncoder>(seal_context_);
    evaluator_ = make_unique<seal::Evaluator>(seal_context_);

    prng_ =
        seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Decryptor> decryptor_;
  unique_ptr<seal::IntegerEncoder> encoder_;
  unique_ptr<seal::Evaluator> evaluator_;
  shared_ptr<UniformRandomGenerator> prng_;

};

BENCHMARK_DEFINE_F(SealFixture, Encode)(benchmark::State& st) {
  seal::Plaintext pt;
  for (auto _ : st) {
    uint64_t val = prng_->generate();
    encoder_->encode(val, pt);
    ::benchmark::DoNotOptimize(pt);
  }
}
BENCHMARK_REGISTER_F(SealFixture, Encode);

BENCHMARK_DEFINE_F(SealFixture, Encrypt)(benchmark::State& st) {
  seal::Plaintext pt;
  seal::Ciphertext ct(seal_context_);
  for (auto _ : st) {
    encoder_->encode(prng_->generate(), pt);
    encryptor_->encrypt(pt, ct);
    ::benchmark::DoNotOptimize(ct);
  }
}
BENCHMARK_REGISTER_F(SealFixture, Encrypt);

BENCHMARK_DEFINE_F(SealFixture, Multiply)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;
  seal::Ciphertext ct(seal_context_);

  encoder_->encode(prng_->generate(), pt_1);
  encoder_->encode(prng_->generate(), pt_2);
  encryptor_->encrypt(pt_1, ct);

  for (auto _ : st) {
    evaluator_->multiply_plain_inplace(ct, pt_2);
    ::benchmark::DoNotOptimize(ct);
  }
}
BENCHMARK_REGISTER_F(SealFixture, Multiply);

BENCHMARK_DEFINE_F(SealFixture, Decrypt)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;
  seal::Ciphertext ct(seal_context_);
  seal::Plaintext result_pt;

  uint64_t val_1 = prng_->generate();
  uint64_t val_2 = prng_->generate();
  encoder_->encode(val_1, pt_1);
  encoder_->encode(val_2, pt_2);
  encryptor_->encrypt(pt_1, ct);
  evaluator_->multiply_plain_inplace(ct, pt_2);

  for (auto _ : st) {
    decryptor_->decrypt(ct, result_pt);
    auto result = encoder_->decode_uint64(result_pt);
    if (result != val_1 * val_2) {
      st.SkipWithError("Result does not match expected");
      return;
    }
  }
}
BENCHMARK_REGISTER_F(SealFixture, Decrypt);

BENCHMARK_DEFINE_F(SealFixture, FullProcess)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;
  seal::Ciphertext ct(seal_context_);
  seal::Plaintext result_pt;

  for (auto _ : st) {
    uint64_t val_1 = prng_->generate();
    uint64_t val_2 = prng_->generate();
    encoder_->encode(val_1, pt_1);
    encoder_->encode(val_2, pt_2);

    encryptor_->encrypt(pt_1, ct);
    evaluator_->multiply_plain_inplace(ct, pt_2);
    decryptor_->decrypt(ct, result_pt);
    auto result = encoder_->decode_uint64(result_pt);
    if (result != val_1 * val_2) {
      st.SkipWithError("Result does not match expected");
      return;
    }
  }
}
BENCHMARK_REGISTER_F(SealFixture, FullProcess);

BENCHMARK_DEFINE_F(SealFixture, PT_NTT_Transform)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;

  uint64_t val_1 = prng_->generate();
  encoder_->encode(val_1, pt_1);

  for (auto _ : st) {
    evaluator_->transform_to_ntt(pt_1, seal_context_->first_parms_id(), pt_2);
    ::benchmark::DoNotOptimize(pt_2);
  }
}
BENCHMARK_REGISTER_F(SealFixture, PT_NTT_Transform);

BENCHMARK_DEFINE_F(SealFixture, CT_NTT_Transform)(benchmark::State& st) {
  seal::Plaintext pt;
  seal::Ciphertext ct(seal_context_);
  seal::Ciphertext ct_2(seal_context_);

  uint64_t val_1 = prng_->generate();
  encoder_->encode(val_1, pt);
  encryptor_->encrypt(pt, ct);


  for (auto _ : st) {
    evaluator_->transform_to_ntt(ct, ct_2);
    ::benchmark::DoNotOptimize(ct_2);
  }
}
BENCHMARK_REGISTER_F(SealFixture, CT_NTT_Transform);

BENCHMARK_DEFINE_F(SealFixture, MultiplyNTT)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;
  seal::Ciphertext ct(seal_context_);

  uint64_t val_1 = prng_->generate();
  uint64_t val_2 = prng_->generate();
  encoder_->encode(val_1, pt_1);
  encoder_->encode(val_2, pt_2);
  evaluator_->transform_to_ntt_inplace(pt_2, seal_context_->first_parms_id());
  encryptor_->encrypt(pt_1, ct);
  evaluator_->transform_to_ntt_inplace(ct);

  for (auto _ : st) {
    evaluator_->multiply_plain_inplace(ct, pt_2);
    ::benchmark::DoNotOptimize(ct);
  }
}
BENCHMARK_REGISTER_F(SealFixture, MultiplyNTT);

BENCHMARK_DEFINE_F(SealFixture, MultiplyNTTWithTransforms)(benchmark::State& st) {
  seal::Plaintext pt_1;
  seal::Plaintext pt_2;
  seal::Plaintext pt_3;
  seal::Ciphertext ct(seal_context_);
  seal::Ciphertext ct_2(seal_context_);

  uint64_t val_1 = prng_->generate();
  uint64_t val_2 = prng_->generate();
  encoder_->encode(val_1, pt_1);
  encoder_->encode(val_2, pt_2);
  encryptor_->encrypt(pt_1, ct);

  for (auto _ : st) {
    evaluator_->transform_to_ntt(pt_2, seal_context_->first_parms_id(), pt_3);
    evaluator_->transform_to_ntt(ct, ct_2);
    evaluator_->multiply_plain_inplace(ct_2, pt_3);
    ::benchmark::DoNotOptimize(ct_2);
  }
}
BENCHMARK_REGISTER_F(SealFixture, MultiplyNTTWithTransforms);
