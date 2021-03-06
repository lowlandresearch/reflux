defmodule Reflux.MDNS.Server do
  @moduledoc """
  UDPServer  to be used by various listening services
  """
  require Logger
  use GenServer

  alias UDPServer.State
  # alias UDPServer.Packet
  # alias Reflux.DNS.Packet

  @port 5353
  @name "Reflux MDNS Server"
  @opts [
    :binary, :inet,
    {:active, true},
    {:add_membership, {{224, 0, 0, 251}, {0,0,0,0}}},
    {:multicast_if, {0, 0, 0, 0}},
    {:multicast_loop, false},
    {:multicast_ttl, 4},
    {:reuseaddr, true},
  ]

  def start_link(_opts) do
    GenServer.start_link(
      __MODULE__,
      [%State{port: @port, name: @name, opts: @opts}],
      name: __MODULE__
    )
  end

  @impl true
  def init([state]) do
    IO.inspect(state)
    UDPServer.init(state)
  end

  @impl true
  def handle_info(
    {:udp, socket, ip, src_port, packet},
    %State{socket: socket} = state
  ) do
    new_count = state.count + 1
    Logger.info(
      "[#{new_count}] #{:inet.ntoa(ip)}:#{src_port}" <>
      " sent: #{packet} "
    )
    {:noreply, %State{state | count: new_count}}
  end

  @impl true
  def terminate(_reason, %State{socket: socket} = state) when socket != nil do
    UDPServer.terminate(state)
  end

end
