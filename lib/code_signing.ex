defmodule CodeSigning do
  @moduledoc """
  Code signing and verification functions for BEAM binaries using Ed25519 signatures.

  All strings for paths need to be passed as charlists for Erlang compatibility.
  """

  @typedoc """
  The filename as a string or the BEAM module binary.
  """
  @type beam :: charlist() | binary()

  @typedoc """
  A tuple of the chunk ID and its binary data.
  """
  @type chunkdata :: {charlist(), binary()}

  @doc """
  Signs the the given BEAM binary or path to `.beam` file using the Ed25519 `secret_key`.

  Returns the modified binary that can be written to a file.

  When given a BEAM binary, it will sign the binary.

  When given a path to a `.beam` file, it will sign the binary without modifying the original file.
  """
  @spec sign(beam(), Ed25519.key()) :: binary
  def sign(module_or_path, secret_key) do
    chunks = module_chunks(module_or_path)

    chunks
    |> sign_bytecode(secret_key)
    |> (&write_signature_attribute(chunks, &1)).()
    |> build_module
  end

  @doc """
  Verifies the signature of the given BEAM binary or path to `.beam` file using the
  Ed25519 `public_key`.

  When given a BEAM binary, it will verify the signature of the binary.

  When given a path to a `.beam` file, it will verify the signature of the binary without
  modifying the original file.
  """
  @spec valid_signature?(beam(), Ed25519.key()) :: boolean
  def valid_signature?(module_or_path, public_key) do
    chunks = module_chunks(module_or_path)
    code = chunks |> code_binary

    chunks
    |> read_signature_attribute
    |> Ed25519.valid_signature?(code, public_key)
  end

  @doc """
  Verifies the signature of the given BEAM binary using the Ed25519 `public_key`. If the
  signature is valid, the module will be loaded.
  """
  @spec load(atom(), binary(), Ed25519.key()) :: :ok | :error
  def load(module, binary, public_key) do
    case valid_signature?(binary, public_key) do
      true ->
        :code.load_binary(module, nil, binary)

        :ok

      _ ->
        :error
    end
  end

  @doc """
  Verifies the signature of the given path to `.beam` file using the
  Ed25519 `public_key`. If the signature is valid, the module will be loaded.

  Module names should be atoms prefixed with Elixir, such as `String.to_atom("Elixir.MyModule")`
  """
  @spec load_file(atom(), charlist(), Ed25519.key()) :: :ok | :error
  def load_file(module, beam_path, public_key) do
    case valid_signature?(beam_path, public_key) do
      true ->
        {:ok, binary, _} = :erl_prim_loader.get_file(beam_path)
        :code.load_binary(module, beam_path, binary)

        :ok

      _ ->
        :error
    end
  end

  @spec sign_bytecode([chunkdata()], Ed25519.key()) :: Ed25519.signature()
  defp sign_bytecode(chunks, secret_key) do
    chunks |> code_binary |> Ed25519.signature(secret_key)
  end

  @spec read_signature_attribute([chunkdata()]) :: Ed25519.signature()
  defp read_signature_attribute(chunks) do
    case :lists.keyfind('Attr', 1, chunks) do
      {'Attr', attributes} ->
        case :erlang.binary_to_term(attributes) |> Keyword.get(:signature) do
          nil -> nil
          signature -> signature |> hd
        end

      _ ->
        nil
    end
  end

  @spec write_signature_attribute([chunkdata()], Ed25519.signature()) :: [chunkdata()]
  defp write_signature_attribute(chunks, signature) do
    case :lists.keyfind('Attr', 1, chunks) do
      {'Attr', attributes} ->
        attribute_list = [signature: [signature]] ++ :erlang.binary_to_term(attributes)
        :lists.keyreplace('Attr', 1, chunks, {'Attr', :erlang.term_to_binary(attribute_list)})

      _ ->
        attribute_list = [signature: [signature]]
        :lists.append(chunks, [{'Attr', :erlang.term_to_binary(attribute_list)}])
    end
  end

  @spec code_binary([chunkdata()]) :: binary
  defp code_binary(chunks) do
    with {'Code', code} <- :lists.keyfind('Code', 1, chunks) do
      code
    end
  end

  @spec module_chunks(beam()) :: [chunkdata()]
  defp module_chunks(module_or_path) do
    with {:ok, _, chunks} <- :beam_lib.all_chunks(module_or_path) do
      chunks
    end
  end

  @spec build_module([chunkdata()]) :: binary
  defp build_module(chunks) do
    with {:ok, binary} <- :beam_lib.build_module(chunks) do
      binary
    end
  end
end
