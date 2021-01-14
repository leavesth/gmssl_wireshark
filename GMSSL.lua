-- @brief GMSSL Protocol dissector plugin
-- @author dzxtyyz.2b.30s.ccs

-- create a new dissector
local NAME = "GMSSL"
local PORT = 443
local GMSSL = Proto(NAME, "GMSSL Protocol")

local fields = GMSSL.fields
fields.ContentType = ProtoField.uint8 (NAME .. ".ContentType", "ContentType")
fields.MajorVersion = ProtoField.uint8 (NAME .. ".MajorVersion", "MajorVersion")
fields.MinorVersion = ProtoField.uint8 (NAME .. ".MinorVersion", "MinorVersion")
fields.length = ProtoField.uint16(NAME .. ".length", "Length")

fields.helloType = ProtoField.uint8(NAME .. ".Hello.Type", "Hello")
fields.helloLength = ProtoField.uint24(NAME .. ".Hello.Length", "Length")
fields.helloMajorVersion = ProtoField.uint8(NAME .. ".Hello.MajorVersion", "MajorVersion")
fields.helloMinorVersion = ProtoField.uint8(NAME .. ".Hello.MinorVersion", "MinorVersion")
fields.helloTime = ProtoField.uint32(NAME .. ".Hello.Time", "Time")
fields.helloRand = ProtoField.bytes(NAME .. ".Hello.Random", "Random")
fields.helloSesIdLen = ProtoField.uint8(NAME .. ".Hello.SesIdLen", "SessionIdLen")
fields.helloSesId = ProtoField.bytes(NAME .. ".Hello.SesId", "SessionId")

fields.helloCipherSuiteLen = ProtoField.uint16(NAME .. ".Hello.CipherSuiteLen", "CipherSuiteLen")
fields.helloCipherSuite = ProtoField.string(NAME .. ".Hello.CipherSuite", "CipherSuite")
fields.helloCipherSuiteValue = ProtoField.uint16(NAME .. ".Hello.CipherSuite.CipherSuiteValue", "CipherSuite")

fields.helloCompessMethodLen = ProtoField.uint8(NAME .. ".Hello.CompressMethodLen", "COmpressMethodLen")
fields.helloCompessMethod = ProtoField.bytes(NAME .. ".Hello.CompressMethod", "CompressMethod")

fields.helloExtensionLen = ProtoField.uint16(NAME .. ".Hello.ExtensionLen", "ExtensionLen")
fields.helloExtension = ProtoField.bytes(NAME .. ".Hello.Extension", "Extension")

fields.helloCertLen = ProtoField.uint24(NAME .. ".Hello.CertLen", "CertLen")
fields.helloCert = ProtoField.bytes(NAME .. ".Hello.CertLen", "CertLen")

fields.keyExchangeLen = ProtoField.uint24(NAME .. ".Hello.KeyExchangeLen", "KeyExchangeLen")
fields.keyExchange = ProtoField.bytes(NAME .. ".Hello.KeyExchange", "KeyExchange")

fields.helloDoneLeng = ProtoField.uint24(NAME .. ".Hello.ServerHelloDoneLen", "Length")

fields.certReqLen = ProtoField.uint24(NAME .. ".Hello.CertReqLen", "Length")
fields.certReq = ProtoField.bytes(NAME .. ".Hello.CertReq", "CertReq")

fields.clientKeyExchange = ProtoField.uint8(NAME .. ".Hello.ClientKeyExchange", "ClientKeyExchange")
fields.clientKeyExchangeLen = ProtoField.uint24(NAME .. ".Hello.ClientKeyExchange", "ClientKeyExchangeLen")
fields.clientKeyExchangeData = ProtoField.bytes(NAME .. ".Hello.ClientKeyExchangeData", "ClientKeyExchangeData")

fields.certVerify = ProtoField.uint8(NAME .. ".Hello.CertVerify", "CertVerify")
fields.certVerifyLen = ProtoField.uint24(NAME .. ".Hello.CertVerifyLen", "CertVerifyLen")
fields.certVerifyData = ProtoField.bytes(NAME .. ".Hello.CertVerifyData", "CertVerifyData")

fields.changeCipherSpecMessage = ProtoField.uint8(NAME .. ".Hello.ChangeCipherSpecMessage", "ChangeCipherSpecMessage")

fields.applicationDataLen = ProtoField.uint24(NAME .. ".Hello.ApplicationDataLen", "ApplicationDataLen")
fields.applicationData = ProtoField.bytes(NAME .. ".Hello.ApplicationData", "ApplicationData")

fields.encryptedHelloData = ProtoField.bytes(NAME .. ".EncryptedHelloData", "EncryptedHelloData")

fields.alertData = ProtoField.bytes(NAME .. ".AlertData", "AlertData")

--local clientHello = GMSSL.fields.clientHello

-- dissect packet
function GMSSL.dissector (tvb, pinfo, tree)	
	local offset = 0
	local isgm = 0
	isgm = tvb(1, 2)
	-- GMSSL version is 1.1
	if (isgm:uint() ~= 0x0101)
	then
		Dissector.get("tls"):call(tvb, pinfo, tree) -- Decode as origial TLS
		return
	end

	local changeCipherOk = false
	-- If GM ssl.
	local subtree = tree:add(GMSSL, tvb())	
	pinfo.cols.protocol = GMSSL.name
	local parseoff = 0
	while (offset < tvb:len())
	do
		local type = tvb(offset, 1)
		subtree:add(fields.ContentType, type)
		local contentType = "Hello"
		local dataType = type:uint()
		
		-- pinfo.cols.info = "ClientHello"
	
		offset = offset + 1	
		type = tvb(offset, 1)
		subtree:add(fields.MajorVersion, type)
		local majorVersion = type
		--subtree:append_text(", MajorVersion: " .. type:uint())
	
		offset = offset + 1	
		type = tvb(offset, 1)
		local minorVersion = type
		local verStr = 
		subtree:add(fields.MinorVersion, type):append_text(string.format(": Version: %d.%d", majorVersion:uint(), minorVersion:uint()))
	
	
		offset = offset + 1
		type = tvb(offset, 2)
		subtree:add(fields.length, type):append_text(": DataLength")
		subtree:append_text(", Length: " .. type:uint())

		offset = offset + 2

		if(dataType == 22)
		then
			contentType = "HandShake"
		elseif(dataType == 20)
		then
			contentType = "ChangeCipherSpec"
		elseif (dataType == 21)
		then
			contentType = "Alert"
		elseif (dataType == 23)
		then
			contentType = "ApplicationData"
			subtree:add(fields.applicationData, tvb(offset, type:uint()))
			offset = offset + type:uint()
		elseif (dataType == 80)
		then
			contentType = "Site2Site"
		else
			contentType = "Unknown"
		end
		subtree:append_text(": " .. contentType)
		
		if(dataType == 20)
		then -- ChangeCipherSpec  one bytes.
			subtree:add(fields.changeCipherSpecMessage, tvb(offset, type:uint()))
			offset = offset + type:uint()
			changeCipherOk = true
		elseif(dataType == 21) -- Alert
		then
			subtree:add(fields.alertData, tvb(offset, type:uint()))
			offset = offset + type:uint()
		elseif(dataType == 22) -- handshake process
		then
			-- After ChangeCipherSuite,It's Maybe A Hello EncryptedData, It's Also Handshake Message
			-- It's May be EncrypteData. If ChangeCipherSpec Completed
			if(changeCipherOk)
			then
				subtree:add(fields.encryptedHelloData, tvb(offset, type:uint()))
				offset = offset + type:uint()
				changeCipherOk = false
			else
				-- parse types.		
				type = tvb(offset, 1)
				if (type:uint() == 1)
				then
					parseoff = parseClientHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 2)
				then
					parseoff = parseServerHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 11)
				then
					--	certificate
					parseoff = parseCertficate(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 12)
				then
					-- server key exchange
					parseoff = parseServerKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 13)
				then
					--	certificate request
					parseoff = parseCertficateRequest(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 14)
				then
					--	server hello done
					parseoff = parseServerHelloDone(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 15)
				then
					--	certificate verify
					parseoff = parseCertificateverify(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 16)
				then
					--	client key exchange
					parseoff = parseClientKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 20)
				then
					--	finished
				end
			end
		end
	end
end

function parseClientHello(tvb, pinfo, tree) 
	local subtree = tree:add_le("ClientHello")
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ClientHello")
	offset = offset + 1
	local length = tvb(offset, 3)
	subtree:add(fields.helloLength, length):append_text(": HelloLength")
	offset = offset + 3

	local majorVersion = tvb(offset, 1)
	offset = offset + 1
	local minorVersion = tvb(offset, 1)
	offset = offset + 1
	subtree:add(fields.helloMajorVersion, majorVersion)
	subtree:add(fields.helloMinorVersion, minorVersion):append_text(": 协议版本:" .. string.format("%d.%d", majorVersion:uint(), minorVersion:uint()))
	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()
	offset = offset + 1
	subtree:add(fields.helloSesIdLen, sessionIdLen)
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	local cipherSuiteLen = tvb(offset, 2):uint()
	subtree:add(fields.helloCipherSuiteLen, cipherSuiteLen)
	offset = offset + 2
	if (cipherSuiteLen >= 2)
	then
		stree = subtree:add(fields.helloCipherSuite,string.format("(%d) Suites", cipherSuiteLen / 2))
		for indx = 1, cipherSuiteLen / 2, 1 do
			stree:add(fields.helloCipherSuiteValue, tvb(offset, 2)):append_text(string.format(": 0x%04X", tvb(offset, 2):uint()))
			offset = offset + 2
		end
	end
	-- compress
	subtree:add(fields.helloCompessMethodLen, tvb(offset, 1))	
	local compressMethodLen = tvb(offset, 1):uint()
	offset = offset + 1
	if (compressMethodLen > 0)
	then
		subtree:add(fields.helloCompessMethod, tvb(offset, compressMethodLen))
		offset = offset + compressMethodLen
	end
	local extensionLen = tvb(offset, 2):uint()	
	subtree:add(fields.helloExtensionLen, tvb(offset, 2))
	offset = offset + 2
	if (extensionLen > 0)
	then
		subtree:add(fields.helloExtension, tvb(offset, extensionLen))
		offset = offset + extensionLen
	end
	return offset
end

-- parse Server Hello
function parseServerHello(tvb, pinfo, tree)
	local subtree = tree:add_le("ServerHello")
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerHello")
	offset = offset + 1
	local length = tvb(offset, 3)
	subtree:add(fields.helloLength, length):append_text(": ServerHelloLength")
	offset = offset + 3

	local majorVersion = tvb(offset, 1)
	offset = offset + 1
	local minorVersion = tvb(offset, 1)
	offset = offset + 1
	subtree:add(fields.helloMajorVersion, majorVersion)
	subtree:add(fields.helloMinorVersion, minorVersion):append_text(": 协议版本:" .. string.format("%d.%d", majorVersion:uint(), minorVersion:uint()))
	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()
	offset = offset + 1
	subtree:add(fields.helloSesIdLen, sessionIdLen)
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	local cipherSuite = tvb(offset, 2):uint()
	subtree:add(fields.helloCipherSuite, cipherSuite)
	offset = offset + 2
	
	-- compress
	subtree:add(fields.helloCompessMethodLen, tvb(offset, 1))	
	local compressMethodLen = tvb(offset, 1):uint()
	offset = offset + 1
	if (compressMethodLen > 0)
	then
		subtree:add(fields.helloCompessMethod, tvb(offset, compressMethodLen))
		offset = offset + compressMethodLen
	end

	local extensionLen = tvb(offset, 2):uint()	
	subtree:add(fields.helloExtensionLen, tvb(offset, 2))
	offset = offset + 2
	if (extensionLen > 0)
	then
		subtree:add(fields.helloExtension, tvb(offset, extensionLen))
		offset = offset + extensionLen
	end

	return offset
end


function parseCertficate(tvb, pinfo, tree)
	local offset = 0

	local subtree = tree:add_le("Certificate")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": Certficate")
	offset = offset + 1
	-- Total Length
	local totalLen = tvb(offset, 3):uint()	
	subtree:add(fields.helloCertLen, tvb(offset, 3)):append_text(": DataLength")
	offset = offset + 3

	local cert0Len = tvb(offset, 3):uint()
	subtree:add(fields.helloCertLen, tvb(offset, 3)):append_text(": CertLength")
	offset = offset + 3

	local paseLens = 0
	while(paseLens < cert0Len)
	do
		-- parse one certs.
		stree = subtree:add(fields.helloCert,string.format("One Certs"))
		stree:add(fields.helloCertLen, tvb(offset, 3))
		local onecertLen = tvb(offset, 3):uint()
		offset = offset + 3
		stree:add(fields.helloCert, tvb(offset, onecertLen))
		offset = offset + onecertLen

		paseLens = paseLens + 3 + onecertLen
	end
	return offset
end

function parseServerKeyExchange(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ServerKeyExchange")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerKeyExchange")
	offset = offset + 1

	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.keyExchangeLen, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3

	subtree:add(fields.keyExchange, tvb(offset, lengs)):append_text(": Length")
	offset = offset + lengs
	return offset
end

function parseServerHelloDone(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ServerHelloDone")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerHelloDone")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.helloDoneLeng, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3
	return offset
end

function parseCertficateRequest(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("CertficateRequest")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": CertficateRequest")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.certReqLen, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3
	subtree:add(fields.certReq, tvb(offset, lengs)):append_text(": CertReq")
	offset = offset + lengs
	return offset
end

function parseClientKeyExchange(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ClientKeyExchange")
	local type = tvb(offset, 1)
	subtree:add(fields.clientKeyExchange, type):append_text(": ClientKeyExchange")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.clientKeyExchangeLen, tvb(offset, 3)):append_text(": ClientKeyExchangeLen")
	offset = offset + 3

	subtree:add(fields.clientKeyExchangeData, tvb(offset, lengs)):append_text(": clientKeyExchangeData")
	offset = offset + lengs
	return offset
end

function parseCertificateverify(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("CertVerify")
	local type = tvb(offset, 1)
	subtree:add(fields.certVerify, type):append_text(": CertVerify")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.certVerifyLen, tvb(offset, 3)):append_text(": CertVerifyLen")
	offset = offset + 3

	subtree:add(fields.certVerifyData, tvb(offset, lengs)):append_text(": CertVerifyData")
	offset = offset + lengs
	return offset
end

-- register this dissector
DissectorTable.get("tcp.port"):add(PORT, GMSSL)