-- Furuno 10010/udp
-- virus.friendly@gmail.com

furuno_protocol = Proto("Furuno", "Furuno Maritime Traffic")

header = ProtoField.bytes("furuno.header", "Header", base.SPACE)
msgtype = ProtoField.uint8("furuno.message_type", "messageType", base.DEC)
msglen = ProtoField.uint16("furuno.message_length", "messageLength", base.DEC)
mac_addr = ProtoField.bytes("furuno.mac_address", "MacAddress", base.COLON)
device_model = ProtoField.string("furuno.device_model", "deviceModel", base.ASCII)
device_modelid = ProtoField.string("furuno.device_model_id", "deviceModelID", base.ASCII)
device_swver = ProtoField.string("furuno.software_version", "softwareVersion", base.ASCII)
device_modelver = ProtoField.string("furuno.device_model_version", "deviceModelVersion", base.ASCII)
device_serialcode = ProtoField.string("furuno.device_serialcode_maybe", "deviceSerialMaybe", base.ASCII)
field_data = ProtoField.bytes("furuno.fielddata", "field data", base.SPACE)
unknown = ProtoField.bytes("furuno.unknown", "Unknown", base.SPACE)

furuno_protocol.fields = {header, msgtype, msglen, mac_addr, device_model, device_modelid, device_swver, device_modelver, device_serialcode, field_data, unknown}

function furuno_protocol.dissector(buffer,pinfo,tree)
	local length = buffer:len()
	if length < 8 then return end
	  
	pinfo.cols.protocol = furuno_protocol.name
	  
	local subtree = tree:add(furuno_protocol, buffer(), "Furuno Protocol Data")
	subtree:add(header, buffer(0,8))
	  
	if buffer(8):len() < 4 then return end
	  
	length = buffer(10,2):uint()
	if buffer(8):len() < length then
		if (buffer(8,1):uint() == 0x1b) and (buffer(8):len() == 32) then
			local msgtree = subtree:add(buffer(8), "Message")
		
			msgtree:add(msgtype, buffer(8,1))
			
			if (buffer(9,2):string() ~= "\01\00") and (buffer(11,1):uint() ~= 0xa2) and (buffer(12,6):string() ~= "\01\00\00\00\00\00") then
				msgtree:add(buffer(9,9), "!!! This is usally 01 00 a2 01 00 00 00 00 00")
			end
			
			msgtree:add(mac_addr, buffer(18,6))
			
			if (buffer(24,5):string() ~= "\0\0\0\0\0") and ((buffer(24,1):uint() ~= 0xf9) and (buffer(25,4):string() ~= "\04\00\12\08")) then
				msgtree:add(buffer(24,5), "!!! This is usually 00s or f9 04 00 0c 08")
			end
			
			if buffer(29):string() ~= "\0\0\0\0\0\0\0\0\0\0\0" then
				msgtree:add(buffer(29), "!!! This is usually 00s")
			end
		end
		return
	end
	  
	local msgtree = subtree:add(buffer(8, length), "Message")
	  
	msgtree:add(msgtype, buffer(8,1))
	  
	if buffer(9,1):uint() ~= 1 then
		msgtree:add(buffer(9,1), "!!! This is usually 0x01")
	end
	  
	msgtree:add(msglen, buffer(10,2))
	  
	if buffer(12,4):string() ~= "\01\00\00\00" then
		msgtree:add(buffer(12,4), "!!! This is usally 01 00 00 00")
	end
  
	if buffer(8,1):uint() == 0 then
		if length >= 16 then
			msgtree:add(device_model, buffer(16,8))
			
			if length > 16 then
				if buffer(24,1):uint() > 1 then
					msgtree:add(buffer(24,1), "!!! This is usally 00 or 01")
				end
			
				if length == 20 then
					if buffer(25):string() ~= "\01\00\00" then
						msgtree:add(buffer(25), "!!! This is usally 00 01 00 00 or 01 01 00 00")
					end
				elseif length == 32 then
					if buffer(25):string() ~= "\01\00\06\00\23\00\21\00\17\00\20\00\22\00\02" then
						msgtree:add(buffer(25), "!!! This is usually 01 01 00 06 00 17 00 15 00 11 00 14 00 16 00 02")
					end
				end
			end
		end
	elseif (buffer(8,1):uint() == 1) or (buffer(8,1):uint() == 20) or (buffer(8,1):uint() == 21) or (buffer(8,1):uint() == 24) or (buffer(8,1):uint() == 28) then
		if length ~= 8 then
			msgtree:add(buffer(10,2), "!!! This is an unusual size for this message type")
		end
	elseif buffer(8,1):uint() == 15 then
		if length ~= 162 then
			msgtree:add(buffer(10,2), "!!! This is an unusual size for this message type")
		else
			--unsure if the next two are correct, why I didnt make them fields
			msgtree:add(buffer(16,1), "Interface:", buffer(16,1):uint())
			msgtree:add(buffer(17,1), "Device:", buffer(17,1):uint())
			
			msgtree:add(mac_addr, buffer(18,6))
			
			if buffer(24,1):uint() ~= 0 then
				msgtree:add(device_modelid, buffer(24,32))
			end
			
			if buffer(56,1):uint() ~= 0 then
				msgtree:add(device_swver, buffer(56,32))
			end
			
			if buffer(88,1):uint() ~= 0 then
				msgtree:add(device_modelver, buffer(88,32))
			end
			
			if buffer(120,1):uint() ~= 0 then
				msgtree:add(device_serialcode, buffer(120,32))
			end
			
			msgtree:add(unknown, buffer(152,8))
			msgtree:add(unknown, buffer(160,8))
			msgtree:add(unknown, buffer(168))
		end
	elseif buffer(8,1):uint() == 16 then
		msgtree:add(buffer(16,4), "Number of Fields", buffer(16,4):uint())
			
		if buffer(20):len() < (buffer(16,4):uint() * 10) then
			msgtree:add(buffer(16,4), "!!! More fields than space")
		else
			for fieldnum = 0,buffer(16,4):uint() -1
			do
				field = subtree:add(buffer(20 + (fieldnum * 10),10), "Field", buffer(20 + (fieldnum * 10),2):uint())
				field:add(field_data, buffer(22 + (fieldnum * 10),8))
			end
		end
	elseif buffer(8,1):uint() == 23 then
		if length ~= 17 then
			msgtree:add(buffer(10,2), "!!! This is an unusual size for this message type")
		else
			if buffer(16,2):uint() ~= 0 then
				msgtree:add(buffer(17,1), "!!! This is usally 00")
			end
			
			msgtree:add(mac_addr, buffer(18,6))
		end
	end
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(10010, furuno_protocol)