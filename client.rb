require 'socket'        # Sockets are in standard library

class Client
  def initialize(host, port)
    @s = TCPSocket.new(host, port)
    @stage = 0
  end

  def connect
    loop {
      if @stage == 0
        # Init Send
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        data = "\x05\x01\x00"
        @s.write data
        puts "Stage 0 sent: " + data.unpack('H*').to_s
        @stage += 1
      elsif @stage == 1
        # Receive
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        # | 1  |   1    |
        # +----+--------+
        ver = @s.read(1)
        if ver != "\x05"
          @s.close
        end
        method = @s.read(1)
        puts "Stage 1 received: " + (ver+method).unpack('H*').to_s
        # Send
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver = "\x05"
        # o  CMD
        # o  CONNECT X'01'
        # o  BIND X'02'
        # o  UDP ASSOCIATE X'03'
        cmd = "\x01"
        rsv = "\x00"
        # o  ATYP   address type of following address
        # o  IP V4 address: X'01' - 4 bytes
        # o  DOMAINNAME: X'03' - the first byte stands for length
        # o  IP V6 address: X'04' - 16 bytes
        atyp = "\x03"
        data = ver + cmd + rsv + atyp + "\x0ewww.google.org" + "\x00\x50"
        @s.write data
        puts "Stage 1 sent: " + data.unpack('H*').to_s
        @stage += 1
      elsif @stage == 2
        # Receive
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver = @s.read(1)
        if ver != "\x05"
          @s.close
        end
        # o  REP    Reply field:
        # o  X'00' succeeded
        # o  X'01' general SOCKS server failure
        # o  X'02' connection not allowed by ruleset
        # o  X'03' Network unreachable
        # o  X'04' Host unreachable
        # o  X'05' Connection refused
        # o  X'06' TTL expired
        # o  X'07' Command not supported
        # o  X'08' Address type not supported
        # o  X'09' to X'FF' unassigned
        rep = @s.read(1)
        rsv = @s.read(1)
        # o  ATYP   address type of following address
        # o  IP V4 address: X'01' - 4 bytes
        # o  DOMAINNAME: X'03' - the first byte stands for length
        # o  IP V6 address: X'04' - 16 bytes
        atyp = @s.read(1)
        if atyp == "\x01"
          bnd_addr = @s.read(4)
        elsif atyp == "\x02"
          len = @s.read(1).ord
          bnd_addr = @s.read(len)
        else
          bnd_addr = @s.read(16)
        end
        bnd_port = @s.read(2)
        puts "Stage 2 received: " + (ver+rep+rsv+atyp+bnd_addr+bnd_port).unpack('H*').to_s
        @stage += 1
      elsif @stage == 3
        @s.write "Hello"
        sleep(3)
      end
    }
    s.close                 # Close the socket when done
  end

end

if __FILE__ == $0
  c = Client.new('localhost', 1080)
  c.connect()
end

