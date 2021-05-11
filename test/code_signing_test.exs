defmodule CodeSigningTest do
  use ExUnit.Case
  doctest CodeSigning

  test "greets the world" do
    assert CodeSigning.hello() == :world
  end
end
