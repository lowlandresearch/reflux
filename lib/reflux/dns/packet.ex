defmodule DNS do
  def int_bool(<< bit :: 1 >>) do
    int_bool(bit)
  end

  def int_bool(n) do
    if n != 0, do: true, else: false
  end

  def bool_int(bool) do
    if (bool), do: 1, else: 0
  end

  def bin_slice(binary, start) do
    binary_part(binary, start, byte_size(binary) - start)
  end
  def bin_slice(binary, start, stop) do
    binary_part(binary, start, stop)
  end
  
  @doc "Simple encoding (no compression)"
  @spec encode_name(binary) :: {:ok, binary} 
  def encode_name(name) do
    {
      :ok,
      name
      |> String.split(".")
      |> Enum.map(fn (s) -> << byte_size(s) >> <> s end)
      |> Enum.join("")
      |> (fn (s) -> s <> "\x00" end).()
    }
  end

  @doc """
  Given a DNS packet, locate and return the binary buffer of resource
  records
  """
  @spec rr_buffer(binary) :: {:ok, binary} | {:error, :atom}
  def rr_buffer(packet) do
    case packet do
      << _tid :: 16, _flags :: 16, _qs :: 16, _a :: 16, _au :: 16,
         _add :: 16, buffer :: binary >> ->
        if byte_size(buffer) > 0 do
          {:ok, buffer}
        else
          {:error, :rr_buffer_empty}
        end
      _ -> {:error, :rr_buffer_malformed}
    end
  end

  @doc """
  Given a DNS packet, locate and return the binary buffer of resource
  records
  """
  def rr_buffer!(packet) do
    case rr_buffer(packet) do
      {:ok, buffer} -> buffer
      {:error, error} -> raise error
    end
  end

  @spec decode_name(binary, binary) :: {:ok, binary} | {:error, :atom}
  def decode_name(packet, buffer) do
    decode_name(packet, [], buffer)
  end

  @spec decode_name(binary, List.t, binary) :: {:ok, binary} | {:error, :atom}
  def decode_name(_data, labels, << 0, _rest :: binary >>) do
    {:ok,
     labels
     |> Enum.reverse
     |> Enum.join(".")}
  end

  @spec decode_name(binary, List.t, binary) :: {:ok, binary} | {:error, :atom}
  def decode_name(packet, labels, buffer) do
    case buffer do
      << 1::1, 1::1, ref :: 14, rest :: binary >> ->
        if ref < (byte_size(packet) - byte_size(rest)) do
          decode_name(
            packet, labels,
            bin_slice(packet, ref)
          )
        else
          {:error, :not_backward_reference}
        end
      << 0::1, 0::1, size :: 6, rest :: binary >> ->
        << label :: bytes-size(size), rest :: binary >> = rest
        decode_name(packet, [label] ++ labels , rest)
      _ -> {:error, :bad_rr_name_encoding}
    end
  end
  
  @spec data_after_name(binary) :: {:ok, binary} | {:error, :atom}
  def data_after_name(buffer) do
    case buffer do
      << 0, buffer :: binary >> -> {:ok, buffer}
      << 1::1, 1::1, _ref :: 14, buffer :: binary >> -> {:ok, buffer}
      << 0::1, 0::1, size :: 6, buffer :: binary >> ->
        data_after_name(bin_slice(buffer, size))
      _ -> {:error, :bad_rr_name_encoding}
    end
  end

  @spec rr_fields(binary) :: {:ok, {map, binary}} | {:error, :atom}
  def rr_fields(buffer) do
    case buffer do
      << type :: 16, flush :: 1, class :: 15, rest :: binary >> ->
        {:ok, {%{type: type, flush: int_bool(flush), class: class}, rest}}
      _ -> {:error, :bad_rr_data}
    end
  end

  @spec rr_answer_fields(binary) :: {:ok, {map, binary}} | {:error, :atom}
  def rr_answer_fields(buffer) do
    case buffer do
      << ttl :: 32, size :: 16, rdata_rest :: binary >> ->
        if byte_size(rdata_rest) >= size do
          << rdata :: bytes-size(size), rest :: binary >> = rdata_rest
          {:ok, {%{ttl: ttl, data: rdata}, rest}}
        else
          require IEx; IEx.pry
          {:error, {:rdata_size_too_large, size, rdata_rest}}
        end
      _ -> {:error, :bad_rr_data}
    end
  end
end

defmodule DNS.RR.Properties do
  @doc """
  The resource record class (e.g. IN) as atom
  """
  @spec class(map) :: :IN | :CH | :unhandled
  def class(%{class: class}) do
    case class do
      1   -> :IN
      3   -> :CH
      _   -> :unhandled
    end
  end

  @doc """
  The resource record type (e.g. A, AAAA, PTR) as atom
  """
  @spec type(map) :: :atom
  def type(%{type: type}) do
    case type do
      1   -> :A
      2   -> :NS
      5   -> :CNAME
      6   -> :SOA
      12  -> :PTR
      15  -> :MX
      16  -> :TXT
      24  -> :SIG
      25  -> :KEY
      28  -> :AAAA
      29  -> :LOC
      33  -> :SRV
      37  -> :CERT
      39  -> :DNAME
      43  -> :DS
      45  -> :IPSECKEY
      46  -> :RRSIG
      47  -> :NSEC
      48  -> :DNSKEY
      50  -> :NSEC3
      51  -> :NSEC3PARAM
      250 -> :TSIG
      251 -> :IXFR
      252 -> :AXFR
      _   -> :unhandled
    end
  end
end

# Elixir binary pattern matching of Integer or Convert Integer to
# binary
# 
# https://stackoverflow.com/a/43073250

defmodule DNS.RR do
  @moduledoc """
  DNS resource record
  """
  
  # import DNS, only: [
  #   bool_int: 1, bin_slice: 2, bin_slice: 3,
  # ]
  
  defstruct [
    name: "",
    type: 0,
    flush: false,
    class: 1,              # RR class (IN by default)
    ttl: 0,                # Time to live
    data: "",              # Data associated with this Resource Record
  ]

  @spec raw_name(binary, binary) :: {:ok, {binary, binary}} | {:error, :atom}
  def raw_name(buffer, name \\ "") do
    # IO.inspect(buffer, binaries: :as_strings, label: "buffer")
    # IO.inspect(name, binaries: :as_strings, label: "name")
    case buffer do
      << 0, buffer :: binary >> ->
        {:ok, {name, buffer}}
      << 1::1, 1::1, ref :: 14, buffer :: binary >> ->
        {:ok, {name <> << 1::1, 1::1, ref >>, buffer}}
      << 0::1, 0::1, size :: 6, buffer :: binary >> ->
        # IO.inspect(size)
        raw_name(
          DNS.bin_slice(buffer, size),
          name <> << 0::1, 0::1, size :: 6 >> <> DNS.bin_slice(buffer, 0, size)
        )
      _ -> {:error, :bad_rr_name_encoding}
    end
  end

  defimpl PacketEncoder do
    @spec to_bitstring(DNS.RR.t) :: binary
    def to_bitstring(rr = %DNS.RR{}) do
      with {:ok, name} <- DNS.encode_name(rr.name) do
        name <> <<
        rr.type :: 16,
          DNS.bool_int(rr.flush) :: 1,
          rr.class :: 15,
          rr.ttl :: 32,
          byte_size(rr.data) :: 16
        >> <> rr.data
      end
    end
  end

  @spec from_bitstring(binary, binary) :: {:ok, {DNS.RR.t, binary}} | {:error, :atom}
  def from_bitstring(packet, buffer) do
    with {:ok, name} <- DNS.decode_name(packet, buffer),
         {:ok, rr_rest} <- DNS.data_after_name(buffer),
         {:ok, {fields, answer_rest}} <- DNS.rr_fields(rr_rest),
         {:ok, {answer_fields, rest}} <- DNS.rr_answer_fields(answer_rest)
      do
      {:ok, {
          %DNS.RR{name: name}
          |> Map.merge(fields)
          |> Map.merge(answer_fields), rest
       }}
    end
  end

end

defmodule DNS.Query do
  @moduledoc """
  DNS Query
  """
  
  import DNS, only: [
    encode_name: 1, decode_name: 2, data_after_name: 1, rr_fields: 1,
  ]
  
  defstruct [
    name: "",
    type: 0,
    flush: false,
    class: 1,
  ]

  defimpl PacketEncoder do
    @spec to_bitstring(DNS.Query.t) :: binary
    def to_bitstring(query = %DNS.Query{}) do
      with {:ok, name} <- encode_name(query.name) do
        name <> <<
          query.type :: 16,
          query.class :: 16,
        >>
      end
    end
  end

  @spec from_bitstring(binary, binary) :: {:ok, {DNS.Query.t, binary}} | {:error, :atom}
  def from_bitstring(packet, buffer) do
    with {:ok, name} <- DNS.decode_name(packet, buffer),
         {:ok, rr_rest} <- DNS.data_after_name(buffer),
         {:ok, {fields, rest}} <- DNS.rr_fields(rr_rest) do
      {:ok, {
          %DNS.Query{name: name}
          |> Map.merge(fields), rest
       }}
    end
  end

end

defmodule DNS.Packet do
  import DNS, only: [
    bool_int: 1, int_bool: 1,
  ]
  
  defstruct [
    tid: 0,
    response: false,
    opcode: 0,
    authoritative: false,
    truncated: false,
    recursion_desired: false,
    recursion_available: false,
    z: 0,
    answer_is_auth: false,
    non_auth_data_ok: false,
    response_code: 0,
    queries: [],
    answers: [],
    nameservers: [],
    additional: [],
  ]

  # @type t :: %__MODULE__{
  #   tid: integer, flags: integer,
  #   questions: integer, answer_rrs: integer,
  #   authority_rrs: integer, additional_rrs: integer,
  #   queries: List.t, answers: List.t, nameservers: [], records: [],
  # }
  # ("Tid",              "\x00\x00"),
  # ("Flags",            "\x84\x00"),
  # ("Question",         "\x00\x00"),
  # ("AnswerRRS",        "\x00\x01"),
  # ("AuthorityRRS",     "\x00\x00"),
  # ("AdditionalRRS",    "\x00\x00"),
  # ("AnswerName",       ""),
  # ("AnswerNameNull",   "\x00"),
  # ("Type",             "\x00\x01"),
  # ("Class",            "\x00\x01"),
  # ("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn.
  # ("IPLen",            "\x00\x04"),
  # ("IP",               "\x00\x00\x00\x00"),

  defimpl PacketEncoder do
    @spec to_bitstring(DNS.Packet.t) :: binary
    def to_bitstring(packet = %DNS.Packet{}) do
      <<
        packet.tid :: 16,
        bool_int(packet.response) :: 1,
        packet.opcode :: 4,
        bool_int(packet.authoritative) :: 1,
        bool_int(packet.truncated) :: 1,
        bool_int(packet.recursion_desired) :: 1,
        bool_int(packet.recursion_available) :: 1,
        packet.z :: 1,
        bool_int(packet.answer_is_auth) :: 1,
        bool_int(packet.non_auth_data_ok) :: 1,
        packet.response_code :: 4,
        Enum.count(packet.queries) :: 16,
        Enum.count(packet.answers) :: 16,
        Enum.count(packet.nameservers) :: 16,
        Enum.count(packet.additional) :: 16
      >> <> (
        packet.queries
        |> Enum.map(&PacketEncoder.to_bitstring/1)
        |> Enum.join("")
      ) <> (
        packet.answers
        |> Enum.map(&PacketEncoder.to_bitstring/1)
        |> Enum.join("")
      ) <> (
        packet.nameservers
        |> Enum.map(&PacketEncoder.to_bitstring/1)
        |> Enum.join("")
      ) <> (
        packet.additional
        |> Enum.map(&PacketEncoder.to_bitstring/1)
        |> Enum.join("")
      )
    end
  end

  def parse_header(packet) do
    case packet do
      <<
        tid :: 16,
        response :: 1,
        opcode :: 4,
        authoritative :: 1,
        truncated :: 1,
        recursion_desired :: 1,
        recursion_available :: 1,
        z :: 1,
        answer_is_auth :: 1,
        non_auth_data_ok :: 1,
        response_code :: 4,
        n_queries :: 16,
        n_answers :: 16,
        n_nameservers :: 16,
        n_additional :: 16,
        rr_rest :: binary
      >> ->
        {
          :ok,
          {%{
              tid: tid,
              response: int_bool(response),
              opcode: opcode,
              authoritative: int_bool(authoritative),
              truncated: int_bool(truncated),
              recursion_desired: int_bool(recursion_desired),
              recursion_available: int_bool(recursion_available),
              z: z,
              answer_is_auth: int_bool(answer_is_auth),
              non_auth_data_ok: int_bool(non_auth_data_ok),
              response_code: response_code,
           }, %{
              n_queries: n_queries,
              n_answers: n_answers,
              n_nameservers: n_nameservers,
              n_additional: n_additional,
           }, rr_rest}
        }
      _ -> {:error, :malformed_dns_header}
    end
  end

  def parse_rrs(n, from_bitstring, packet, buffer, rrs \\ [])

  def parse_rrs(0, _from_bitstring, _packet, buffer, rrs) do
    {:ok, {rrs |> Enum.reverse, buffer}}
  end

  def parse_rrs(n, from_bitstring, packet, buffer, rrs) do
    # IO.inspect(buffer)
    with {:ok, {rr, buffer}} <- from_bitstring.(packet, buffer) do
      parse_rrs(n - 1, from_bitstring, packet, buffer, [rr] ++ rrs)
    end
  end

  @spec from_bitstring(binary) :: {:ok, DNS.Packet.t}
  def from_bitstring(packet) do
    with {:ok, {header, counts, rest}} <- parse_header(packet),
         {:ok, {questions, rest}} <- parse_rrs(
           counts.n_queries, &DNS.Query.from_bitstring/2, packet, rest
         ),
         {:ok, {answers, rest}} <- parse_rrs(
           counts.n_answers, &DNS.RR.from_bitstring/2, packet, rest
         ),
         {:ok, {nameservers, rest}} <- parse_rrs(
           counts.n_nameservers, &DNS.RR.from_bitstring/2, packet, rest
         ),
         {:ok, {additional, ""}} <- parse_rrs(
           counts.n_additional, &DNS.RR.from_bitstring/2, packet, rest
         ) do
      %DNS.Packet{}
      |> Map.merge(header)
      |> Map.merge(
        %{queries: questions, answers: answers,
          nameservers: nameservers, additional: additional}
      )
    end
  end
  
  
  @doc """
  What is the response code (as an atom) for this DNS packet?
  """
  @spec response_code(map) :: :atom
  def response_code(%{response_code: code}) do
    case code do
      0   -> :NOERROR
      1   -> :FORMERR
      2   -> :SERVFAIL
      3   -> :NXDOMAIN
      4   -> :NOTIMPL
      5   -> :REFUSED
      6   -> :YXDOMAIN
      7   -> :YXRRSET
      8   -> :NXRRSET
      9   -> :NOTAUTH
      10  -> :NOTZONE
      16  -> :BADVERS_OR_BADSIG
      17  -> :BADKEY
      18  -> :BADTIME
      19  -> :BADMODE
      20  -> :BADNAME
      21  -> :BADALG
      22  -> :BADTRUNC
      _   -> :unhandled
    end
  end
end

