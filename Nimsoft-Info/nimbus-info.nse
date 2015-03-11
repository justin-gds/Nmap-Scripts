local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
This script enumerates a CA Nimsoft Robot using the "nimbus" protocol. 
The status information gathered reveals detailed information about the Nimsoft
domain including the robot and hub information, IP addresses, local 
hostnames, the robot mode, the specific OS version including service pack, the 
server architecture, the SSL mode and specific version, among others. 

CA Unified Infrastructure Manager, formerly known as Nimsoft, is a scalable IT
monitoring solution. The solution is typically installed on managed servers, and
communicates using the closed source "nimbus" protocol. 

The commands executed by this script in order to enumerate the target Robot are:
 - _status
 - get_info
 - gethub
 - probe_checkin
]]

---
-- @usage
-- nmap --script nimbus-info --script-args nimbus-info.timeout=5 -p <port> <target>
--
-- @args nimbus-info.timeout
--       Set the timeout in seconds. The default value is 5.
--
-- @output
-- PORT      STATE SERVICE
-- 48000/tcp open  unknown
-- | nimbus-getinfo: 
-- |   robotname: ie9win7
-- |   robotip: 10.X.X.X
-- |   hubname: 
-- |   hubip: 162.26.136.95
-- |   domain: none
-- |   origin: 
-- |   source: IE9Win7
-- |   robot_device_id: DF842C8209237C42AED75CEF681E88AE2
-- |   robot_mode: 1
-- |   hubrobotname: 
-- |   log_level: 0
-- |   log_file: controller.log
-- |   license: 0
-- |   requests: 43
-- |   uptime: 851
-- |   started: 1420735200
-- |   os_major: Windows
-- |   os_minor: Windows 7 Enterprise Edition, 32-bit
-- |   os_version: 6.1.7601
-- |   os_description: Service Pack 1 Build 7601
-- |   os_user1: 
-- |   os_user2: 
-- |   processor_type: Intel(R) Core(TM) i5-3230M CPU @ 2.60GHz
-- |   workdir: C:\Program Files\Nimsoft
-- |   current_time: 1420736051
-- |   access_0: 0
-- |   access_1: 0
-- |   access_2: 0
-- |   access_3: 0
-- |   access_4: 0
-- |   timezone_diff: 28800
-- |   timezone_name: Pacific Standard Time
-- |   spoolport: 48001
-- |_  last_inst_change: 1411993600

-- Version 0.1
-- Created 2015-01-09 v0.1 - created by Sam Bertram, Gotham Digital Science (sbertram@gdssecurity.com, sammbertram@gmail.com)

author = "Sam Bertram"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.number == 48000 and port.state == "open"
end

action = function( host, port )

  stdnse.print_debug(1, "Starting %s action", nmap.registry.args[SCRIPT_NAME])

  -- set timeout
  local timeout = tonumber(nmap.registry.args['nimbus-info.timeout'])
  if not timeout or timeout <= 0 then timeout = 5000 else timeout = timeout * 1000 end

  local result = {}

  -- open the socket
  socket = nmap.new_socket()
  socket:set_timeout(timeout)

  -- create the catch function
  catch = function() 
  socket:close() 
  return
  end

  try = nmap.new_try(catch)

  -- table containing the command_name, filter, packet
  local packets = {

    getinfo = { 

      -- request packet structure, get_info
      -- 00000000  6e 69 6d 62 75 73 2f 31  2e 30 20 31 30 39 20 32 nimbus/1 .0 109 2
      -- 00000010  38 0d 0a 6d 74 79 70 65  00 37 00 34 00 31 30 30 8..mtype .7.4.100
      -- 00000020  00 63 6d 64 00 37 00 39  00 67 65 74 5f 69 6e 66 .cmd.7.9 .get_inf
      -- 00000030  6f 00 73 65 71 00 31 00  32 00 30 00 74 73 00 31 o.seq.1. 2.0.ts.1
      -- 00000040  00 31 31 00 31 34 32 30  37 34 34 33 34 36 00 66 .11.1420 744346.f
      -- 00000050  72 6d 00 37 00 31 38 00  31 30 2e 32 30 2e 30 2e rm.7.18. 10.XX.X.
      -- 00000060  31 30 33 2f 35 31 33 36  34 00 74 6f 75 74 00 31 XXX/5136 4.tout.1
      -- 00000070  00 34 00 31 38 30 00 61  64 64 72 00 37 00 30 00 .4.180.a ddr.7.0.
      -- 00000080  69 6e 74 65 72 66 61 63  65 73 00 31 00 32 00 30 interfac es.1.2.0
      -- 00000090  00 72 6f 62 6f 74 00 37  00 31 00 00             .robot.7 .1..

      -- regex filter string to start with    
      "robotname", 

      -- finally build the packet to send
      "nimbus/1.0 109 28\r\nmtype\x007\x004\x00100\x00cmd\x007\x009\x00get_info\x00seq\x001\x002\x000\x00ts\x001\x0011\x001111111111\x00frm\x007\x0018\x00"..host.ip.."/44444\x00tout\x001\x004\x00180\x00addr\x007\x000\x00interfaces\x001\x002\x000\x00robot\x007\x001\x00\x00"
    };

    status = {

      -- request packet structure, _status
      -- 00000000  6e 69 6d 62 75 73 2f 31  2e 30 20 31 30 38 20 31 nimbus/1 .0 108 1
      -- 00000010  33 0d 0a 6d 74 79 70 65  00 37 00 34 00 31 30 30 3..mtype .7.4.100
      -- 00000020  00 63 6d 64 00 37 00 38  00 5f 73 74 61 74 75 73 .cmd.7.8 ._status
      -- 00000030  00 73 65 71 00 31 00 32  00 30 00 74 73 00 31 00 .seq.1.2 .0.ts.1.
      -- 00000040  31 31 00 31 34 32 30 37  34 34 31 37 39 00 66 72 11.14207 44179.fr
      -- 00000050  6d 00 37 00 31 38 00 31  30 2e 32 30 2e 30 2e 31 m.7.18.1 0.20.0.1
      -- 00000060  30 33 2f 35 31 33 32 34  00 74 6f 75 74 00 31 00 03/51324 .tout.1.
      -- 00000070  34 00 31 38 30 00 61 64  64 72 00 37 00 30 00 64 4.180.ad dr.7.0.d
      -- 00000080  65 74 61 69 6c 00 31 00  32 00 31 00             etail.1. 2.1.

      -- regex filter string to start with
      "name",

      -- finally build the packet to send
      "nimbus/1.0 108 0\r\nmtype\x007\x004\x00100\x00cmd\x007\x008\x00_status\x00seq\x001\x002\x000\x00ts\x001\x0011\x001111111111\x00frm\x007\x0021\x00"..host.ip.."/44444\x00tout\x001\x004\x00180\x00addr\x007\x000\x00"
    };

    gethub = {

      -- request packet structure, gethub
      -- 00000000  6e 69 6d 62 75 73 2f 31  2e 30 20 31 30 37 20 30 nimbus/1 .0 107 0
      -- 00000010  0d 0a 6d 74 79 70 65 00  37 00 34 00 31 30 30 00 ..mtype. 7.4.100.
      -- 00000020  63 6d 64 00 37 00 37 00  67 65 74 68 75 62 00 73 cmd.7.7. gethub.s
      -- 00000030  65 71 00 31 00 32 00 30  00 74 73 00 31 00 31 31 eq.1.2.0 .ts.1.11
      -- 00000040  00 31 34 32 30 37 33 35  38 35 38 00 66 72 6d 00 .1420735 858.frm.
      -- 00000050  37 00 31 38 00 31 30 2e  32 30 2e 30 2e 31 30 33 7.18.10. 20.0.103
      -- 00000060  2f 36 30 32 36 30 00 74  6f 75 74 00 31 00 34 00 /60260.t out.1.4.
      -- 00000070  31 38 30 00 61 64 64 72  00 37 00 30 00          180.addr .7.0.

      -- regex filter string to start with
      "name",

      -- finally build the packet to send
      "nimbus/1.0 107 0\r\nmtype\x007\x004\x00100\x00cmd\x007\x008\x00gethub\x00seq\x001\x002\x000\x00ts\x001\x0011\x001111111111\x00frm\x007\x0021\x00"..host.ip.."/44444\x00tout\x001\x004\x00180\x00addr\x007\x000\x00"
    };

    probecheckin = {
  
      -- request packet structure, probe_checkin
      -- 00000000  6e 69 6d 62 75 73 2f 31  2e 30 20 31 31 35 20 31 nimbus/1 .0 115 1
      -- 00000010  31 0d 0a 6d 74 79 70 65  00 37 00 34 00 31 30 30 1..mtype .7.4.100
      -- 00000020  00 63 6d 64 00 37 00 31  34 00 70 72 6f 62 65 5f .cmd.7.1 4.probe_
      -- 00000030  63 68 65 63 6b 69 6e 00  73 65 71 00 31 00 32 00 checkin. seq.1.2.
      -- 00000040  30 00 74 73 00 31 00 31  31 00 31 34 32 30 37 33 0.ts.1.1 1.142073
      -- 00000050  30 39 31 34 00 66 72 6d  00 37 00 31 38 00 31 30 0914.frm .7.18.10
      -- 00000060  2e 32 30 2e 30 2e 31 30  33 2f 36 30 31 38 36 00 .20.0.10 3/60186.
      -- 00000070  74 6f 75 74 00 31 00 34  00 31 38 30 00 61 64 64 tout.1.4 .180.add
      -- 00000080  72 00 37 00 30 00 74 79  70 65 00 31 00 32 00 31 r.7.0.ty pe.1.2.1
      -- 00000090  00                                               .

      -- regex filter string to start with
      "domain",

      -- finally build the packet to send
      "nimbus/1.0 115 11\r\nmtype\x007\x004\x00100\x00cmd\x007\x0014\x00probe_checkin\x00seq\x001\x002\x000\x00ts\x001\x0011\x001111111111\x00frm\x007\x0018\x00"..host.ip.."/44444\x00tout\x001\x004\x00180\x00addr\x007\x000\x00type\x00\x31\x00\x32\x00\x31\x00"
    };
  }

  -- connect to the socket
  stdnse.print_debug(1, "Socket connecting to %s/%d.",host.ip, port.number)
  try(socket:connect(host.ip, port.number))
  stdnse.print_debug(1, "Socket connected")
  
  -- loop through the packets to send
  for key, value in pairs(packets) do

    cmd = key
    filter = value[1]
    pkt = value[2]

    -- send the packet
    stdnse.print_debug(1, "Sending '%s' packet of %d bytes.", cmd, string.len(pkt))
    stdnse.print_debug(2, "%q",pkt)
    try(socket:send(pkt))

    local status, recv = socket:receive()
    stdnse.print_debug(2, "Receive status: %s", status)

    -- if there was no error receiving data from the socket
    if status then
      stdnse.print_debug(1, "Received %d bytes of data.", string.len(recv))
      stdnse.print_debug(2, "%q",recv)

      -- strip the header from the message returned
      recv = string.match(recv, filter..".*")

      if recv then

        -- add packet command header in output
        table.insert(result, string.format("%s:", cmd))

        -- explode on null characters
        local explode = string.split(recv,"\x00")

        -- loop through the result and match on every 1st, 5th, 9th, etc. once a 
        -- match is made, get the +3 index. this will be the value in the key
        -- table. only match when the key is a string to prevent null characters
        -- from messing with the formatted output
        for i = 1, #explode do
          if i % 4 == 1 and string.find(explode[i], '%S+') then
            table.insert(result, string.format("  %s: %s", explode[i], explode[i+3]))
          end
        end
      end
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end

-- http://lua-users.org/wiki/SplitJoin
function string:split( inSplitPattern, outResults )

   if not outResults then
      outResults = { }
   end
   local theStart = 1
   local theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
   while theSplitStart do
      table.insert( outResults, string.sub( self, theStart, theSplitStart-1 ) )
      theStart = theSplitEnd + 1
      theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
   end
   table.insert( outResults, string.sub( self, theStart ) )
   return outResults
end
