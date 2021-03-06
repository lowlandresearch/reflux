defmodule UDPServer.State do
  @doc """
  UDPServer configuration state

  port (integer) : port number 1-65535
  opts (List) : keyword list of options
  name (String.t) : name of server
  socket (%Socket) : socket reference associated for this server
  count (integer) : number of packets processed
  """
  defstruct [
    :port, :opts, name: "UDP Server", socket: nil, count: 0,
  ]
  @type t :: %__MODULE__{
    port: integer, opts: list, name: String.t, socket: reference,
    count: integer,
  }
end

defmodule UDPServer.Packet do
  @doc """
  Struct for UDP response packet
  
  ip :: tuple
  src_port :: integer
  packet :: String.t
  """
  defstruct [
    ip: nil, src_port: nil, packet: nil
  ]
  @type t :: %__MODULE__{
    ip: tuple, src_port: integer, packet: String.t
  }
end

defmodule UDPServer do
  @moduledoc """
  UDPServer helper funcitons to be used by various listening services
  """
  alias UDPServer.State
  require Logger

  def init(%State{} = state) do
    {:ok, socket} = :gen_udp.open(state.port, state.opts)
    {:ok, port} = :inet.port(socket)
    Logger.info("#{state.name}: listening on port #{port}")
    {:ok, %{state | socket: socket, port: port}}
  end

  def terminate(%State{socket: socket} = state) do
    Logger.info("#{state.name}: closing port #{state.port}")
    :ok = :gen_udp.close(socket)
  end

end
