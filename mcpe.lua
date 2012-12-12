-- MCPE Protocol dissector by Intyre
mcpe_proto = Proto("MCPE","MCPE Protocol")
local subtree

function mcpe_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "MCPE"
    
    local packetID = buffer(0,1)
    local length = buffer:len()
    
    pinfo.cols.info = "Data 0x" .. packetID
    subtree = tree:add(mcpe_proto,buffer(),"Data 0x" .. packetID)
    subtree:add(packetID,"Data Length: " .. length)
    subtree:add(buffer(0,1), "Packet ID: 0x" ..buffer(0,1))
    
	if (packetID:uint() == 0x02) then
		pinfo.cols.info = "ID_UNCONNECTED_PING_OPEN_CONNECTIONS: 0x02"
		subtree:add(buffer(1,8),"Ping ID: " .. buffer(1,8))
		subtree:add(buffer(9,16),"Magic: " ..  buffer(9,16))
	elseif (packetID:uint() == 0x1c) then
		pinfo.cols.info = "ID_UNCONNECTED_PING_OPEN_CONNECTIONS: 0x1c"
		subtree:add(buffer(1,8), "Ping ID: " .. buffer(1,8))
		subtree:add(buffer(9,8), "Server ID: " ..buffer(9,8))
		subtree:add(buffer(17,16), "MAGIC: " .. buffer(17,16))
		subtree:add(buffer(33,2), "Length: " .. buffer(33,2):uint())
		subtree:add(buffer(35,11),"Indentifier: " .. buffer(35,11):string())
		subtree:add(buffer(46,-1),"Server name: " .. buffer(46,-1):string())
	elseif (packetID:uint() == 0x05) then
		pinfo.cols.info = "ID_OPEN_CONNECTION_REQUEST_1: 0x05"
		subtree:add(buffer(1,16),"Magic: " .. buffer(1,16))
    	subtree:add(buffer(17,1),"Protocol version: " .. buffer(17,1))
    	subtree:add(buffer(18,-1),"Null Payload")
	elseif (packetID:uint() == 0x06) then
		pinfo.cols.info = "ID_OPEN_CONNECTION_REPLY_1: 0x06"
		subtree:add(buffer(1,16),"Magic: " .. buffer(1,16))
    	subtree:add(buffer(17,8),"Server ID: " .. buffer(17,8))
    	subtree:add(buffer(25,1),"Server security: " .. buffer(25,1))
    	subtree:add(buffer(26,-1),"MTU Size: " .. buffer(26,-1):uint())
	elseif (packetID:uint() == 0x07) then
		pinfo.cols.info = "ID_OPEN_CONNECTION_REQUEST_2: 0x07"
		subtree:add(buffer(1,16),"Magic: " .. buffer(1,16))
    	subtree:add(buffer(17,5),"Sercurity + Cookie: " .. buffer(17,5))
	    subtree:add(buffer(22,2),"Server Port: " .. buffer(22,2):uint())
	    subtree:add(buffer(24,2),"MTU Size: " .. buffer(24,2):uint())
	    subtree:add(buffer(26,8),"Client ID: " .. buffer(26,8))
	elseif (packetID:uint() == 0x08) then
		pinfo.cols.info = "ID_OPEN_CONNECTION_REPLY_2: 0x08"
		subtree:add(buffer(1,16),"Magic: " .. buffer(1,16))
    	subtree:add(buffer(17,8),"Server ID: " .. buffer(17,8))
    	subtree:add(buffer(25,5),"Security + Cookie: " .. buffer(25,5))
    	subtree:add(buffer(30,2),"Client port: " .. buffer(30,2):uint())
    	subtree:add(buffer(32,2),"MTU Size: " .. buffer(32,2):uint())
    	subtree:add(buffer(34,1),"Security: " .. buffer(34,1))
	elseif (packetID:uint() == 0xa0) then
		pinfo.cols.info = "NACK Packet: 0xa0"
		subtree:add(buffer(1,2),"Unknown: " .. buffer(1,2))
   	 	subtree:add(buffer(3,1),"Additional Packet: " .. buffer(3,1))
	    if(buffer(3,1):uint() == 0x01) then  
	        subtree:add(buffer(4,-1),"Packet number: " .. buffer(4,-1):le_uint())
	    else
	        pinfo.cols.info:append(" Multiple")
	        getTime = subtree:add(buffer(4,6),"Multiple nack's") 
		    getTime:add(buffer(4,3),"Packet number: " .. buffer(4,3):le_uint())
	        getTime:add(buffer(7,3),"Packet number: " .. buffer(7,3):le_uint())
	    end
	elseif (packetID:uint() == 0xc0) then
		pinfo.cols.info = "ACK Packet: 0xc0"
		subtree:add(buffer(1,2),"Unknown: " .. buffer(1,2))
   	 	subtree:add(buffer(3,1),"Additional Packet: " .. buffer(3,1))
	    if(buffer(3,1):uint() == 0x01) then  
	        subtree:add(buffer(4,-1),"Packet number: " .. buffer(4,-1):le_uint())
	    else
	        pinfo.cols.info:append(" Multiple")
	        getTime = subtree:add(buffer(4,6),"Multiple ack's") 
		    getTime:add(buffer(4,3),"Packet number: " .. buffer(4,3):le_uint())
	        getTime:add(buffer(7,3),"Packet number: " .. buffer(7,3):le_uint())
	    end
	elseif (packetID:uint() == 0x80 or packetID:uint() == 0x84 or packetID:uint() == 0x88 or packetID:uint() == 0x8c) then
		subtree:add(buffer(1,3), "Packet number: " .. buffer(1,3):le_uint())
		data = buffer(4,-1)
		len = data:len() -4
		plength = 0
		i = 0
		total = 0
		while i<len do
			iS = i
			idp = data(i,1):uint()
			i = i + 1
			plength = data(i,2):uint() / 8
			i = i + 2
			if idp == 0x00 then

			elseif idp == 0x40 then
				i = i + 3
			elseif idp == 0x60 then
				i = i + 7
			end
			iX = i
			
			if data(i,1):uint() == 0x82 then
				part = subtree:add(data(i,plength),"LoginPacket")
				dataStart(part,data,iS,idp)
				i = i + 1				
				slength = data(i,2):uint()
				i = i + 2
				getString(part,data,i)
				i = i + slenght
				part:add(data(i,4), "Int: " .. data(i,4))
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4))
				
			elseif data(i,1):uint() == 0x84 then
				part = subtree:add(data(i,plength), "ReadyPacket")
				dataStart(part,data,iS,idp);
				i = i + 1				
				part:add(data(i,1), "Byte: " .. data(i+7,1))
				i = i + 1
				
			elseif data(i,1):uint() == 0x85 then
				part = subtree:add(data(i,plength), "MessagePacket")
				dataStart(part,data,iS,idp);
				i = i + 1				
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x86 then
				part = subtree:add(data(i,plength), "SetTimePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,2), "Short: " .. data(i,2):le_uint())
				i = i + 2
				part:add(data(i,2), "Short: " .. data(i,2):le_uint())
				i = i + 2
				
			elseif data(i,1):uint() == 0x87 then
				part = subtree:add(data(i,plength), "StartGamePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x88 then
				part = subtree:add(data(i,plength), "AddMobPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x89 then
				part = subtree:add(data(i,plength), "AddPlayerPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x8a then
				part = subtree:add(data(i,plength), "RemovePlayerPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x8c then
				part = subtree:add(data(i,plength), "AddEntityPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x8d then
				part = subtree:add(data(i,plength), "RemoveEntityPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Byte: " .. data(i,4):uint())
				i = i + 4
				
			elseif data(i,1):uint() == 0x8e then
				part = subtree:add(data(i,plength), "AddItemEntityPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
				part:add(data(i,4), "Float: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Float: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Float: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				
			elseif data(i,1):uint() == 0x8f then
				part = subtree:add(data(i,plength), "TakeItemEntityPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				
			elseif data(i,1):uint() == 0x90 then
				part = subtree:add(data(i,plength), "MoveEntityPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x93 then
				part = subtree:add(data(i,plength), "MoveEntityPacket_PosRot")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "X: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Y: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Z: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Yaw: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Pitch: " .. data(i,4):float())
				i = i + 4
				
				
			elseif data(i,1):uint() == 0x94 then
				part = subtree:add(data(i,plength), "MovePlayerPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(buffer(i,4), "Unknown: " .. buffer(i,4))
				i = i + 4
				part:add(buffer(i,4), "Pos X: " .. buffer(i,4):float())
				i = i + 4
				part:add(buffer(i,4), "Pos Y: " .. buffer(i,4):float())
				i = i + 4
				part:add(buffer(i,4), "Pos Z: " .. buffer(i,4):float())
				i = i + 4
				part:add(buffer(i,4), "Yaw: " .. buffer(i,4):float())
				i = i + 4
				part:add(buffer(i,4), "Pitch: " .. buffer(i,4):float())
				i = i + 4
				
				
			elseif data(i,1):uint() == 0x95 then
				part = subtree:add(data(i,plength), "PlaceBlockPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				
			elseif data(i,1):uint() == 0x96 then
				part = subtree:add(data(i,plength), "RemoveBlockPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Entity ID: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "X: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Z: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,1), "Y: " .. data(i,1):uint())
				i = i + 1
				
			elseif data(i,1):uint() == 0x97 then
				part = subtree:add(data(i,plength), "UpdateBlockPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x98 then
				part = subtree:add(data(i,plength), "AddPaintingPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x99 then
				part = subtree:add(data(i,plength), "ExplodePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x9a then
				part = subtree:add(data(i,plength), "LevelEventPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x9b then
				part = subtree:add(data(i,plength), "TileEventPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				
			elseif data(i,1):uint() == 0x9c then
				part = subtree:add(data(i,plength), "EntityEventPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Entity ID: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Event: " .. data(i,4):uint())
				i = i + 4
				
				
			elseif data(i,1):uint() == 0x9d then
				part = subtree:add(data(i,plength), "RequestChunkPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "X: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Z: " .. data(i,4):uint())
				i = i + 4
				
			elseif data(i,1):uint() == 0x9f then
				part = subtree:add(data(i,plength), "PlayerEquipmentPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa0 then
				part = subtree:add(data(i,plength), "InteractPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa1 then
				part = subtree:add(data(i,plength), "UseItemPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa2 then
				part = subtree:add(data(i,plength), "PlayerActionPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa3 then
				part = subtree:add(data(i,plength), "SetEntityDataPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa4 then
				part = subtree:add(data(i,plength), "SetEntityMotionPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
				
			elseif data(i,1):uint() == 0xa5 then
				part = subtree:add(data(i,plength), "SetHealthPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,1), "Byte: " .. data(i,1):uint())
				i = i + 1
				
			elseif data(i,1):uint() == 0xa6 then
				part = subtree:add(data(i,plength), "SetSpawnPositionPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa7 then
				part = subtree:add(data(i,plength), "AnimatePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa8 then
				part = subtree:add(data(i,plength), "RespawnPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xa9 then
				part = subtree:add(data(i,plength), "Packet::Packet(void)")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xaa then
				part = subtree:add(data(i,plength), "DropItemPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i+7,1), "Byte: " .. data(i+7,1):uint())
				
			elseif data(i,1):uint() == 0xab then
				part = subtree:add(data(i,plength), "ContainerOpenPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xac then
				part = subtree:add(data(i,plength), "ContainerClosePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xad then
				part = subtree:add(data(i,plength), "ContainerSetSlotPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xae then
				part = subtree:add(data(i,plength), "ContainerSetDataPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xaf then
				part = subtree:add(data(i,plength), "ContainerSetContentPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xb0 then
				part = subtree:add(data(i,plength), "ContainerAckPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xb1 then
				part = subtree:add(data(i,plength), "ChatPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xb2 then
				part = subtree:add(data(i,plength), "SignUpdatePacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0xb3 then
				part = subtree:add(data(i,plength), "AdventureSettingsPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x09 then
				
				part = subtree:add(data(i,plength), "Unknown")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				part:add(data(i,1), "Unknown: " .. data(i,1))
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
				
			elseif data(i,1):uint() == 0x10 then
				part = subtree:add(data(i,plength), "Unknown")
				pinfo.cols.info:append(" <-- Unknown!!")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,4), "Cookie: " .. data(i,4))
				i = i + 4
				part:add(data(i,1), "Security: " .. data(i,1))
				i = i + 1
				part:add(data(i,2), "Client Port: " .. data(i,2):uint())
				i = i + 2
				for j=0,9 do
					part:add(data(i,7), "Unknown: " .. data(i,7))
					i = i + 7
				end
				part:add(data(i,2), "Unknown: " .. data(i,2))
				i = i + 2
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				
			elseif data(i,1):uint() == 0x13 then
				part = subtree:add(data(i,plength), "Unknown")
				pinfo.cols.info:append(" <-- Unknown!!")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,4), "Cookie: " .. data(i,4))
				i = i + 4
				part:add(data(i,1), "Security: " .. data(i,1))
				i = i + 1
				part:add(data(i,2), "Client Port: " .. data(i,2):uint())	
				i = i + 2
				part:add(data(i,5), "Unknown: " .. data(i,5))
				i = i + 5
				for j=0,8 do
					part:add(data(i,7), "Unknown: " .. data(i,7))
					i = i + 7
				end
				part:add(data(i,2), "Unknown: " .. data(i,2))
				i = i + 2
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				part:add(data(i,8), "Unknown: " .. data(i,8))
				i = i + 8
				
			elseif data(i,1):uint() == 0x83 then
				part = subtree:add(data(i,plength), "LoginStatusPacket")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
			elseif data(i,1):uint() == 0x86 then
				part = subtree:add(data(i,plength), "SetTimePacket")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,2), "Short: " .. data(i,2):uint())	
				i = i + 2
				part:add(data(i,2), "Short: " .. data(i,2):uint())
				i = i + 2
					
			elseif data(i,1):uint() == 0x87 then
				part = subtree:add(data(i,plength), "StartGamePacket")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,4), "Seed: " .. data(i,4):uint())	
				i = i + 4
				part:add(data(i,4), "Unknown: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Game Mode: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Unknown: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "X: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Y: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Z: " .. data(i,4):float())
				i = i + 4
				
			elseif data(i,1):uint() == 0x89 then
				part = subtree:add(data(i,plength), "AddPlayerPacket")
				dataStart(part,data,iS,idp)
				i = i + 1
				part:add(data(i,8), "Client iD: " .. data(i,8))	
				i = i + 8
				slength = data(i,2):uint()
				part:add(data(i,2), "Length: " .. slength)
				i = i + 2
				part:add(data(i,slength), "Name: " .. data(i,slength):string())
				i = i + slenght
				part:add(data(i+slength,4), "Entity ID: " .. data(i+slength,4):uint())
				i = i + 4
				part:add(data(i,4), "X: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Y: " .. data(i,4):float())
				i = i + 4
				part:add(data(i,4), "Z: " .. data(i,4):float())
				i = i + 4
				pinfo.cols.info:append(" <-- Stuff missing!!")
				
			elseif data(i,1):uint() == 0x9e then
				part = subtree:add(data(i,plength), "ChunkDataPacket")
				dataStart(part,data,iS,idp);
				i = i + 1
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				part:add(data(i,4), "Int: " .. data(i,4):uint())
				i = i + 4
				
			else 
				part = subtree:add(data(i,plength),"Unknown")
				dataStart(part,data,iS,idp);
				i = i + 1
				pinfo.cols.info:append(" <-- Unknown!!")
			end
			i = iX + plength
			total = total + 1
		end
		pinfo.cols.info:append(" (" .. total .. ")")
    end
    
end


function getString(tree,data,i)
	slength = data(i,2):uint()
	tree:add(data(i,2), "Length: " .. slength)
	tree:add(data(i+2,slength), "Name: " .. data(i+2,slength):string())
end

function dataStart(tree,data,i,idp)
	tree:add(data(i,1), "Container: " .. data(i,1))
	tree:add(data(i+1,2), "Data length: " .. plength)
	if data(i,1):uint() == 0x00 then
		i = i + 3
	elseif data(i,1):uint() == 0x40 then
		tree:add(data(i+3,3), "Packet counter: " .. data(i+3,3):le_uint())
		i = i + 6
	elseif data(i,1):uint() == 0x60 then
		tree:add(data(i+3,3), "Packet counter: " .. data(i+3,3):le_uint())
		tree:add(data(i+6,4), "Unknown: " .. data(i+6,4):le_uint())
		i = i + 10
	end
	tree:add(data(i,1), "MCPE ID: " .. data(i,1))
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(19132,mcpe_proto)