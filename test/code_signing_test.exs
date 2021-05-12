defmodule CodeSigningTest do
  use ExUnit.Case
  doctest CodeSigning

  @example_beam Path.expand("./fixtures/example.beam", __DIR__) |> String.to_charlist()

  test "signature matches" do
    bytecode = build_test_module()

    {secret_key, public_key} = Ed25519.generate_key_pair()

    signed_bytecode = CodeSigning.sign(bytecode, secret_key)

    assert CodeSigning.valid_signature?(signed_bytecode, public_key) == true
  end

  test "signature doesn't match" do
    bytecode = build_test_module()

    {secret_key, _public_key} = Ed25519.generate_key_pair()

    signed_bytecode = CodeSigning.sign(bytecode, secret_key)

    # generate a different key pair to test against
    {_alternate_secret_key, alternate_public_key} = Ed25519.generate_key_pair()

    assert CodeSigning.valid_signature?(signed_bytecode, alternate_public_key) == false
  end

  test "missing signature" do
    unsigned_bytecode = build_test_module()

    {_secret_key, public_key} = Ed25519.generate_key_pair()

    assert CodeSigning.valid_signature?(unsigned_bytecode, public_key) == false
  end

  test "missing attribute section" do
    bytecode = build_test_module()

    {:ok, {_, stripped_bytecode}} = :beam_lib.strip(bytecode)

    {secret_key, public_key} = Ed25519.generate_key_pair()

    signed_bytecode = CodeSigning.sign(stripped_bytecode, secret_key)

    assert CodeSigning.valid_signature?(signed_bytecode, public_key) == true
  end

  test "signing of a file" do
    {secret_key, public_key} = Ed25519.generate_key_pair()

    signed_bytecode = CodeSigning.sign(@example_beam, secret_key)

    assert CodeSigning.valid_signature?(signed_bytecode, public_key) == true
  end

  defp build_test_module do
    with ignore_conflict_option <- Code.get_compiler_option(:ignore_module_conflict),
         :ok <- Code.put_compiler_option(:ignore_module_conflict, true),
         {_, bytecode} <-
           Code.compile_string("""
             defmodule Xyz do
               def sum(a, b) do
                 a + b
               end
             end
           """)
           |> hd,
         :ok <- Code.put_compiler_option(:ignore_module_conflict, ignore_conflict_option) do
      bytecode
    end
  end
end
