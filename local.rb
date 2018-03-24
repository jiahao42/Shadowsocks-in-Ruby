require 'socket'                 # Get sockets from stdlib
require './utils'

class Local
  def initialize()
    @utils = Utils.new
    @config = @utils.config
    @port = @config['local_port']
    @server_addr = @config['server']
    @server_port = @config['server_port']
    @utils.init_cipher(@config['encrypt-method'])
    @local = TCPServer.new(@port)    # Listen
  end

  def run()
    counter = 0
    loop {
      counter += 1
      Thread.start (@local.accept) {|client| 
        Thread.current["id"] = counter;
        thread_run(client);
        puts "Thread [" + Thread.current["id"].to_s + "] is destroyed"
      }
      puts "Thread [" + counter.to_s + "] is created"
    }
  end
  def thread_run(client)
    stage = 0
    server = TCPSocket.open(@server_addr, @server_port)
    loop {                           # Servers run forever
      if stage == 0
        # Receive
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        ver = client.read(1) # VER
        if ver != "\x05"
          client.close
        end
        n_methods = client.read(1) # NMETHODS
        methods = client.read(n_methods.ord) # METHODS
        puts "Stage 0 received: " + (ver+n_methods+methods).unpack('H*').to_s
        # Send
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        # | 1  |   1    |
        # +----+--------+
        data = "\x05\x00"
        client.write data
        puts "Stage 0 sent: " + data.unpack('H*').to_s
        stage += 1
      elsif stage == 1
        # Receive
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver = client.read(1)
        if ver != "\x05"
          client.close
        end
        # o  CMD
        # o  CONNECT X'01'
        # o  BIND X'02'
        # o  UDP ASSOCIATE X'03'
        cmd = client.read(1)
        rsv = client.read(1)
        # o  ATYP   address type of following address
        # o  IP V4 address: X'01' - 4 bytes
        # o  DOMAINNAME: X'03' - the first byte stands for length
        # o  IP V6 address: X'04' - 16 bytes
        atyp = client.read(1)
        target_addr = ''
        if atyp == "\x01"
          dst_addr = client.read(4)
          target_addr = @utils.bin2ipv4(dst_addr)
          server.write "\x01" + dst_addr
        elsif atyp == "\x03"
          len = client.read(1)
          dst_addr = client.read(len.ord)
          target_addr = @utils.bin2domain(dst_addr, len.ord)
          server.write "\x03" + len + dst_addr
        elsif atyp == "\x04"
          dst_addr = client.read(16)
          # server.write "\x04" + dst_addr
        end
        dst_port = client.read(2)
        server.write dst_port
        target_port = @utils.bin2num(dst_port)
        puts "Stage 1: " + (ver+cmd+rsv+atyp+dst_addr+dst_port).unpack('H*').to_s
        puts "Stage 1: trying to connect " + target_addr + ":" + target_port.to_s
        # Send
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        data = "\x05" + "\x00" + "\x00" + "\x01" + "\x00\x00\x00\x00" + "\x22\x22"
        puts "Stage 1 Sent: " + data.unpack('H*').to_s
        client.write data
        stage += 1
      else
        handle_tcp(client, server)
        break;
      end
    }
  end

  $blockSize = 1024 * 100
  def handle_tcp(client, server)
    loop {
      ready = select([client, server], nil, nil)
      # puts ready[0]
      if ready[0].include? client
          # client -> server
          data = client.recv($blockSize)
          if data.empty?
              puts "client end closed connection"
              break
          end
          data = @utils.encrypt(data)
          # puts 'data encrypted, length: ' + data.length.to_s
          server.write(data)
          
      end
      if ready[0].include? server
          # server -> client
          data = server.recv($blockSize)
          if data.empty?
              puts "server end closed connection"
              break
          end
          data = @utils.decrypt(data)
          # puts 'data decrypted, length: ' + data.length.to_s
          client.write(data)
      end
    }
  end
end

if __FILE__ == $0
  s = Local.new()
  s.run()
end