defmodule CodeSigning.MixProject do
  use Mix.Project

  def project do
    [
      app: :code_signing,
      version: "0.1.0",
      elixir: "~> 1.11",
      source_url: "https://github.com/benknowles/code_signing",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ed25519, "~> 1.3"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Elixir code signing and verification by embedding Ed25519 signatures in BEAM files.
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Ben Knowles"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/benknowles/code_signing"
      }
    ]
  end
end
