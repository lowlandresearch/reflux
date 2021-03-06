defmodule PacketDecoder do
  @moduledoc """
  Given network packet data as a bitstring, this behaviour responsible
  for decoding it into the relevant data structure.
  """

  @callback from_bitstring(bitstring) :: String.t
  
end

defprotocol PacketEncoder do
  @moduledoc """
  Given some packet data structure, this protocol is responsible for
  encoding that information as network-packet-ready bitstrings
  """

  @doc "Encode struct as bitstring (i.e. network data)"
  @spec to_bitstring(map) :: {:ok, term} | {:error, {:atom, String.t}}
  def to_bitstring(packet)
end

