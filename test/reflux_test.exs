defmodule RefluxTest do
  use ExUnit.Case
  doctest Reflux

  test "greets the world" do
    assert Reflux.hello() == :world
  end
end
