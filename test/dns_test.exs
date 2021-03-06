defmodule DNSTest do
  use ExUnit.Case
  doctest DNS

  test "greets the world" do
    assert Reflux.hello() == :world
  end
end
