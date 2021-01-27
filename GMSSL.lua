-- @brief GMSSL Protocol dissector plugin
-- @author ccs
-- @date 20210113

-- create a new dissector
local NAME = "GMSSL"
local PORT = 443
local GMSSL = Proto(NAME, "GMSSL Protocol")

local cuiteTable = {}  -- Cipher Suite Tables
local extenTable = {}  -- Extensions Tables
local compMethod = {}  -- Compression Methods Tables
local cipherKeyExgMthod = {} -- Cipher Key Exchange Method. For eg. DH/ECDH/RSA/PSA...

local g_cipherSuite = 0 -- g_cipherSuite Is the server selected CipherSuiteID

local fields = GMSSL.fields
fields.ContentType = ProtoField.uint8 (NAME .. ".ContentType", "ContentType")
fields.version = ProtoField.string (NAME .. ".Version", "Version")
fields.length = ProtoField.uint16(NAME .. ".length", "Length")

fields.type16 = ProtoField.uint16(NAME .. ".Type16", "Type")
fields.length16 = ProtoField.uint16(NAME .. ".Length16", "Length")

fields.handshakeProtol = ProtoField.string(NAME .. ".HandShakeProtol", "Handshake Protocol")
fields.handshakeType = ProtoField.string(NAME .. ".HandShakeType", "Handshake Type")

fields.helloTime = ProtoField.uint32(NAME .. ".Time", "Time")
fields.helloRand = ProtoField.bytes(NAME .. ".Random", "Random")
fields.helloSesIdLen = ProtoField.uint8(NAME .. ".SesIdLen", "SessionIdLen")
fields.helloSesId = ProtoField.bytes(NAME .. ".SesId", "SessionId")

fields.cipherSuiteLen = ProtoField.uint16(NAME .. ".CipherSuiteLen", "Cipher Suites Length")
fields.cipherSuite = ProtoField.string(NAME .. ".CipherSuite", "Cipher Suites")
fields.cipherSuiteValue = ProtoField.string(NAME .. ".CipherSuiteValue", "Cipher Suite")

fields.compessMethodLen = ProtoField.uint8(NAME .. ".CompressMethodLen", "Compression Methods Length")
fields.compessMethods = ProtoField.string(NAME .. ".CompressMethod", "Compress Methods")
fields.compessMethod = ProtoField.string(NAME .. ".CompressMethod", "Compress Method")

fields.helloExtensionLen = ProtoField.uint16(NAME .. ".ExtensionLen", "ExtensionLen")
fields.helloExtension = ProtoField.bytes(NAME .. ".Extension", "Extension")
fields.extensionMain = ProtoField.string(NAME .. ".extensionMain", "Extension")

fields.certNode = ProtoField.string(NAME .. ".CertNode", "Certificate")
fields.certLen = ProtoField.uint24(NAME .. ".CertLen", "Certificate Length")
fields.cert = ProtoField.bytes(NAME .. ".Cert", "Cert")
fields.certReq = ProtoField.bytes(NAME .. ".CertReq", "CertReq")
fields.certVerifyData = ProtoField.bytes(NAME .. ".CertVerifyData", "CertVerifyData")

fields.keyExchange = ProtoField.bytes(NAME .. ".KeyExchange", "KeyExchange")
fields.keyExchangePara = ProtoField.string(NAME .. "KeyExchangePara", "KeyExchangePara")

fields.changeCipherSpecMessage = ProtoField.uint8(NAME .. ".ChangeCipherSpecMessage", "ChangeCipherSpecMessage")
fields.applicationData = ProtoField.bytes(NAME .. ".ApplicationData", "ApplicationData")
fields.encryptedHelloData = ProtoField.string(NAME .. ".EncryptedHelloData", "Handshake Protocol")
fields.alertData = ProtoField.bytes(NAME .. ".AlertData", "AlertData")

-- dissect packet
function GMSSL.dissector (tvb, pinfo, tree)
	initTables()

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
	local maintree = tree:add(GMSSL, tvb())
	pinfo.cols.protocol = GMSSL.name
	local parseoff = 0
	local infoMsg = ""
	while (offset < tvb:len())
	do
		local type = tvb(offset, 1)
		local startOffset = offset
		local contentType = "Hello"
		local dataType = type:uint()
		
		offset = offset + 1
		local majorVersion = tvb(offset, 1)
		local minorVersion = tvb(offset + 1, 1)
		local versions = tvb(offset, 2)
		
		offset = offset + 2
		local dataLength = tvb(offset, 2)
		offset = offset + 2

        --local subtree = maintree:add(GMSSL, tvb(startOffset, dataLength:uint() + 5))
        local subtree = maintree:add(GMSSL, tvb(startOffset))
		subtree:add(fields.ContentType, type)
		subtree:add(fields.version, versions, string.format("GMSSL %d.%d (0x%04X)", majorVersion:uint(), minorVersion:uint(), versions:uint()))
		subtree:add(fields.length, dataLength)

		type = dataLength -- The Next Code use type....

		if(dataType == 22)
		then
			contentType = "HandShake Protocol"
		elseif(dataType == 20)
		then
			contentType = "Change Cipher Spec Protocol"
		elseif (dataType == 21)
		then
			contentType = "Alert"
		elseif (dataType == 23)
		then
			contentType = "ApplicationData"
            --subtree:add(fields.applicationData, tvb(offset, type:uint()))
            subtree:add(fields.applicationData, tvb(offset))
			offset = offset + type:uint()
			infoMsg = infoMsg .. "Application Data;"
		elseif (dataType == 80)
		then
			contentType = "Site2Site"
		else
			contentType = "Unknown"
		end
		subtree:append_text(": " .. contentType)

		if(dataType == 20)
		then -- ChangeCipherSpec  one bytes.
			subtree:append_text(": Change Cipher Spec")
			infoMsg = infoMsg .. "Change Cipher Spec;"
			subtree:add(fields.changeCipherSpecMessage, tvb(offset, type:uint()))
			offset = offset + type:uint()
			changeCipherOk = true
		elseif(dataType == 21) -- Alert
		then
			subtree:append_text(": Alert")
			infoMsg = infoMsg .. "Alert;"
			subtree:add(fields.alertData, tvb(offset, type:uint()))
			offset = offset + type:uint()
		elseif(dataType == 22) -- handshake process
		then
			-- After ChangeCipherSuite,It's Maybe A Hello EncryptedData, It's Also Handshake Message
			-- It's May be EncrypteData. If ChangeCipherSpec Completed
			if(changeCipherOk)
			then
				subtree:append_text(": Encrypted HandShake Message")
				infoMsg = infoMsg .. "Encrypted HandShake Message;"
				subtree:add(fields.encryptedHelloData, tvb(offset, type:uint()), "Encrypted Handshake Message")
				offset = offset + type:uint()
				changeCipherOk = false
			else
				-- parse types.
				type = tvb(offset, 1)
				if (type:uint() == 1)
				then
					subtree:append_text(": Client Hello")
					infoMsg = infoMsg .. "Client Hello;"
					parseoff = parseClientHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 2)
				then
					subtree:append_text(": Server Hello")
					infoMsg = infoMsg .. "Server Hello;"
					parseoff = parseServerHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 11)
				then
					--	certificate
					subtree:append_text(": Certficate")
					infoMsg = infoMsg .. "Certficate;"
					parseoff = parseCertficate(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 12)
				then
					-- server key exchange
					subtree:append_text(": Server Key Exchange")
					infoMsg = infoMsg .. "Server Key Exchange;"
					parseoff = parseServerKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 13)
				then
					--	certificate request
					subtree:append_text(": Certificate Request")
					infoMsg = infoMsg .. "Certificate Request;"
					parseoff = parseCertficateRequest(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 14)
				then
					--	server hello done
					subtree:append_text(": Server Hello Done")
					infoMsg = infoMsg .. "Server Hello Done;"
					parseoff = parseServerHelloDone(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 15)
				then
					--	certificate verify
					subtree:append_text(": Certificate Verify")
					infoMsg = infoMsg .. "Certificate Verify;"
					parseoff = parseCertificateverify(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 16)
				then
					--	client key exchange
					subtree:append_text(": Client Key Exchange")
					infoMsg = infoMsg .. "Client Key Exchange;"
					parseoff = parseClientKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 20)
				then
					--	finished
					subtree:append_text(": Finished")
					infoMsg = infoMsg .. "Finished;"
				end
			end
		end
	end

	pinfo.cols.info = infoMsg
end

function parseClientHello(tvb, pinfo, tree) 
	--local subtree = tree:add_le("ClientHello")
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	offset = offset + 1
	local length = tvb(offset, 3)
	offset = offset + 3

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + length:uint()), "ClientHello")

	subtree:add(fields.handshakeType, type, string.format("Client hello (%d)", type:uint()))
	subtree:add(fields.length, length)

	subtree:add(fields.version, tvb(offset, 2), string.format("GMSSL %d.%d (0x%04X)", tvb(offset, 1):uint(), tvb(offset + 1, 1):uint(), tvb(offset, 2):uint()))
	offset = offset + 2
	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()
	offset = offset + 1
	subtree:add(fields.helloSesIdLen, tvb(offset, 1))
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	local cipherSuiteLen = tvb(offset, 2):uint()
	subtree:add(fields.cipherSuiteLen, tvb(offset, 2))
	offset = offset + 2
	if (cipherSuiteLen >= 2)
	then
		stree = subtree:add(fields.cipherSuite, tvb(offset, cipherSuiteLen), string.format("(%d) Suites", cipherSuiteLen / 2))
		for indx = 1, cipherSuiteLen / 2, 1 do
			stree:add(fields.cipherSuiteValue, tvb(offset, 2), string.format("%s (0x%04X)", getCipherSuite(tvb(offset, 2):uint()), tvb(offset, 2):uint()))
			offset = offset + 2
		end
	end
	-- compress
	local parseCompressOffset = parseCompressions(tvb(offset):tvb(), pinfo, subtree)
	offset = offset + parseCompressOffset
	
	local parseExtenOffset = parseExtensions(tvb(offset):tvb(), pinfo, subtree)
	offset = offset + parseExtenOffset
	return offset
end

-- parse Server Hello
function parseServerHello(tvb, pinfo, tree)
	
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	offset = offset + 1
	local length = tvb(offset, 3)

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + length:uint()), "ServerHello")
	subtree:add(fields.handshakeType, type, string.format("Server hello (%d)", type:uint()))
	subtree:add(fields.length, length)
	offset = offset + 3

	subtree:add(fields.version, tvb(offset, 2), string.format("GMSSL %d.%d (0x%04X)", tvb(offset, 1):uint(), tvb(offset + 1, 1):uint(), tvb(offset, 2):uint()))
	offset = offset + 2

	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()	
	subtree:add(fields.helloSesIdLen, tvb(offset, 1))
	offset = offset + 1
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	g_cipherSuite = tvb(offset, 2):uint() -- g_cipherSuite Is the server selected CipherSuiteID
	subtree:add(fields.cipherSuite, tvb(offset, 2), string.format("%s (0x%04X)", getCipherSuite(g_cipherSuite), g_cipherSuite))
	offset = offset + 2
	
	-- selected compress methods.
	subtree:add(fields.compessMethod, tvb(offset, 1), getCompressMethodById(tvb(offset, 1):uint()))
	offset = offset + 1
	
	-- Next Maybe Not Extensions.
	local parseExtenOffset = parseExtensions(tvb(offset):tvb(), pinfo, subtree)
	offset = offset + parseExtenOffset
	return offset
end

function parseCompressions(tvb, pinfo, tree)
	local offset = 0
	tree:add(fields.compessMethodLen, tvb(offset, 1))
	local compressMethodLen = tvb(offset, 1):uint()
	offset = offset + 1
	local compMethodTree = tree:add(fields.compessMethods, tvb(offset, compressMethodLen), string.format("(%d methods)", compressMethodLen))
	if (compressMethodLen > 0)
	then
		for indx = 1, compressMethodLen, 1 do
			local compMethodId = tvb(offset, 1):uint()
			compMethodTree:add(fields.compessMethod, tvb(offset, 1), getCompressMethodById(compMethodId))
			offset = offset + 1
		end
	end
	return offset
end

function getCompressMethodById(compMethodId)
	if (nil == compMethod[compMethodId])
	then
		return string.format("Unknown Compress Method (%d)", compMethodId)
	end
	return string.format("%s (%d)", compMethod[compMethodId], compMethodId)
end

function parseCertficate(tvb, pinfo, tree)
	local offset = 0
	local type = tvb(offset, 1)
	offset = offset + 1
	-- Total Length
	local totalLen = tvb(offset, 3)
	offset = offset + 3

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + totalLen:uint()), "Certificate")

	subtree:add(fields.handshakeType, type, string.format("Certificate (%d)", type:uint()))
	subtree:add(fields.length, totalLen)

	local cert0Len = tvb(offset, 3):uint()
	subtree:add(fields.certLen, tvb(offset, 3))
	offset = offset + 3

	local paseLens = 0
	while(paseLens < cert0Len)
	do
		-- parse one certs.		
		local onecertLen = tvb(offset, 3):uint()
		local stree = subtree:add(fields.certNode, tvb(offset, onecertLen), string.format("(%d bytes)", onecertLen))
		stree:add(fields.certLen, tvb(offset, 3))
		offset = offset + 3
		stree:add(fields.cert, tvb(offset, onecertLen))
		offset = offset + onecertLen
		paseLens = paseLens + 3 + onecertLen
	end
	return offset
end

function parseServerKeyExchange(tvb, pinfo, tree)
	local offset = 0
	local type = tvb(offset, 1)
	local lengs = tvb(offset + 1, 3)
	offset = offset + 4

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + lengs:uint()), "Server Key Exchange")

	subtree:add(fields.handshakeType, type, string.format("Server Key Exchange (%d)", type:uint()))
	subtree:add(fields.length, lengs)

	-- Server Key Exchange support DH/ECDH/PSK/RSA/ECJPAKE
	parseKeyExchangeByCuite(tvb(offset, lengs:uint()):tvb(), pinfo, subtree)
	offset = offset + lengs:uint()
	return offset
end

function parseCertficateRequest(tvb, pinfo, tree)

	local offset = 0
	local type = tvb(offset, 1)
	local lengs = tvb(offset + 1, 3)
	offset = offset + 4

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + lengs:uint()), "CertficateRequest")
	subtree:add(fields.handshakeType, type, string.format("CertficateRequest (%d)", type:uint()))
	subtree:add(fields.length, lengs)

	subtree:add(fields.certReq, tvb(offset, lengs:uint()))
	offset = offset + lengs:uint()
	return offset
end

function parseServerHelloDone(tvb, pinfo, tree)

	local offset = 0
	local type = tvb(offset, 1)
	local lengs = tvb(offset + 1, 3)
	offset = offset + 4

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + lengs:uint()), "Server Hello Done")
	subtree:add(fields.handshakeType, type, string.format("Server Hello Done (%d)", type:uint()))
	subtree:add(fields.length, lengs)

	offset = offset + lengs:uint()
	return offset
end

function parseClientKeyExchange(tvb, pinfo, tree)

	local offset = 0
	local type = tvb(offset, 1)
	local lengs = tvb(offset + 1, 3)
	offset = offset + 4

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + lengs:uint()), "Client Key Exchange")
	subtree:add(fields.handshakeType, type, string.format("Client Key Exchange (%d)", type:uint()))
	subtree:add(fields.length, lengs)

	parseKeyExchangeByCuite(tvb(offset, lengs:uint()):tvb(), pinfo, subtree)
	
	offset = offset + lengs:uint()
	return offset
end

function parseCertificateverify(tvb, pinfo, tree)

	local offset = 0
	local type = tvb(offset, 1)
	local lengs = tvb(offset + 1, 3)
	offset = offset + 4

	local subtree = tree:add(fields.handshakeProtol, tvb(0, 4 + lengs:uint()), "Certificate Verify")
	subtree:add(fields.handshakeType, type, string.format("Certificate Verify (%d)", type:uint()))
	subtree:add(fields.length, lengs)

	subtree:add(fields.certVerifyData, tvb(offset, lengs:uint()))
	offset = offset + lengs:uint()
	return offset
end

-- Parse Extensions, Maybe Have No extensions.
-- Before parse, We must detect the head.
function parseExtensions(tvb, pinfo, tree)
	if (tvb:len() < 1)
	then
		return 0
	end
	if (tvb:len() > 4)
	then
		local content = tvb(0, 1):uint() -- Try to parse it as content.
		local ver = tvb(1, 2):uint() -- Try to parse it as Version.
		--Next Content is Not Extensions. Also Handshake Protocol
		if (content == 0x16 and ver == 0x0101)
		then
			return 0 -- No Extensions and other type parsed.
		end
	end
	-- Now, The buf is extensions.
	local offset = 0
	local extensionLen = tvb(offset, 2):uint()
	tree:add(fields.helloExtensionLen, tvb(offset, 2))
	offset = offset + 2
	if (extensionLen > 0)
	then
		-- Extension format is type:2 length: 2 ExtenData
		splitExtensions(tvb(offset, extensionLen):tvb(), pinfo, tree)
		--tree:add(fields.helloExtension, tvb(offset, extensionLen))
		offset = offset + extensionLen
	end
	return offset
end
function splitExtensions(tvb, pinfo, tree)
	local offset = 0
	local buflen = tvb:len()
	while(offset < buflen)
	do
		local extenType = tvb(offset, 2):uint()
		local extenLen = tvb(offset + 2, 2):uint()
		local subExtenTree = tree:add(fields.extensionMain, tvb(offset, 4 + extenLen), string.format("%s (len=%d)", getExtensionType(extenType), extenLen))
		subExtenTree:add(fields.type16, tvb(offset, 2))
		subExtenTree:add(fields.length16, tvb(offset + 2, 2))
		offset = offset + 4
		if (extenLen > 0)
		then
			subExtenTree:add(fields.helloExtension, tvb(offset, extenLen))
		end
		offset = offset + extenLen
	end

	return offset
end

--Get The Extension Type
function getExtensionType(extenType)	
	local retStr = extenTable[extenType]
	if (retStr == nil)
	then
		return "Unknown"
	end
	return retStr
end
-- Get cipher suite by Cipher ID.

function getCipherSuite(cuiteId)	
	local retStr = cuiteTable[cuiteId]
	if (retStr == nil)
	then
		return "NotFound CipherSuite"
	end
	return retStr
end

local KEX_DHE_DSS     = 0x10
local KEX_DHE_PSK     = 0x11
local KEX_DHE_RSA     = 0x12
local KEX_DH_ANON     = 0x13
local KEX_DH_DSS      = 0x14
local KEX_DH_RSA      = 0x15
local KEX_ECDHE_ECDSA = 0x16
local KEX_ECDHE_PSK   = 0x17
local KEX_ECDHE_RSA   = 0x18
local KEX_ECDH_ANON   = 0x19
local KEX_ECDH_ECDSA  = 0x1a
local KEX_ECDH_RSA    = 0x1b
local KEX_KRB5        = 0x1c
local KEX_PSK         = 0x1d
local KEX_RSA         = 0x1e
local KEX_RSA_PSK     = 0x1f
local KEX_SRP_SHA     = 0x20
local KEX_SRP_SHA_DSS = 0x21
local KEX_SRP_SHA_RSA = 0x22
local KEX_TLS13       = 0x23
local KEX_ECJPAKE     = 0x24
local KEX_IBSDH       = 0x90 -- For SM9
local KEX_IBC         = 0x91 -- For SM9
-- Parse KeyExchange By g_Cuite
function parseKeyExchangeByCuite(tvb, pinfo, tree)
	local offset = 0
	local kexMethod = cipherKeyExgMthod[g_cipherSuite]
	if (nil == kexMethod)
	then
		kexMethod = 0
	end
	if (kexMethod == KEX_DH_ANON or kexMethod == KEX_DH_DSS or kexMethod == KEX_DH_RSA or kexMethod == KEX_DHE_DSS
	or  kexMethod == KEX_DHE_RSA)
	then
		--	KeyEx DH
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("DH")
	elseif(kexMethod == KEX_ECDH_ANON or kexMethod == KEX_ECDH_ECDSA or kexMethod == KEX_ECDH_RSA 
	or kexMethod == KEX_ECDHE_ECDSA or kexMethod == KEX_ECDHE_RSA)
	then
		--	KeyEx ECDH
		local subtree = tree:add(fields.keyExchangePara, tvb(0, tvb:len()), "EC Diffie-Hellman Client Params")
		local parseRet = parseEcParameter(tvb, pinfo, subtree)
		offset = offset + parseRet
		if (offset >= tvb:len())
		then
			return
		end
		parseRet = parseEcPoint(tvb(offset):tvb(), pinfo, subtree)
		offset = offset + parseRet
		if (offset >= tvb:len())
		then
			return
		end
		-- GMSSL Maybe have no signature Algo set.
		--parseRet = parseSignatureAlgo(tvb(offset), pinfo, subtree)
		--offset = offset + parseRet
		parseRet = parseSignature(tvb(offset), pinfo, subtree)
		offset = offset + parseRet
	elseif (kexMethod == KEX_PSK)
	then
		-- KexEx PSK
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("PSK")
	elseif (kexMethod == KEX_RSA)
	then
		-- KeyEx RSA
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("RSA")
	elseif (kexMethod == KEX_RSA_PSK)
	then
		-- KeyEx RSAPSK
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("RSAPSK")
	elseif (kexMethod == KEX_ECJPAKE)
	then
		-- KEX_ECJPAKE
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("ECJPAKE")
	else
		-- Not Regconized Key Exchange Methods.
		tree:add(fields.keyExchange, tvb(0, tvb:len())):append_text("Can't Regconiaed Key Exchange Methods")
	end
end

fields.curveType = ProtoField.uint8(NAME .. ".CurveType", "Curve Type")
fields.namedCurve = ProtoField.uint16(NAME .. ".NamedCurve", "Named Curve")
function parseEcParameter(tvb, pinfo, tree)
	local offset = 0
	local curve_type = tvb(offset, 1)
	tree:add(fields.curveType, curve_type)
	offset = offset + 1
	if (curve_type:uint() ~= 3)
	then
		return offset -- only named_curves are supported
	end
	local namedCurve = tvb(offset, 2)
	tree:add(fields.curveType, namedCurve)
	offset = offset + 2
	return offset
end

-- parse EcPoint, pubkey
fields.ecPointLen = ProtoField.uint8(NAME .. ".EcPointLen", "Pubkey Length")
fields.ecPoint = ProtoField.bytes(NAME .. ".EcPoint", "Pubkey")
function parseEcPoint(tvb, pinfo, tree)
	local offset = 0
	local pubkeyLen = tvb(offset, 1)
	offset = offset + 1
	tree:add(fields.ecPointLen, pubkeyLen)
	tree:add(fields.ecPoint,tvb(offset, pubkeyLen:uint()))
	offset = offset + pubkeyLen:uint()
	return offset
end
-- parse signature
fields.signatureAlgorithm = ProtoField.uint16(NAME .. ".SignatureAlgorithm", "Signature Algorithm")
fields.signatureHashAlgorithm = ProtoField.uint8(NAME .. ".SignatureHashAlgorithm", "Signature Hash Algorithm Hash")
fields.signatureSignAlgorithm = ProtoField.uint8(NAME .. ".SignatureHashAlgorithm", "Signature Hash Algorithm Signature")
function parseSignatureAlgo(tvb, pinfo, tree)
	local offset = 0

	local subtree = tree:add(fields.signatureAlgorithm, tvb(offset, 2))
	subtree:add(fields.signatureHashAlgorithm, tvb(offset, 1))
	subtree:add(fields.signatureHashAlgorithm, tvb(offset + 1, 1))
	offset = offset + 2
	return offset
end
fields.signatureLength = ProtoField.uint16(NAME .. ".SignatureLength", "Signature Length")
fields.signature = ProtoField.bytes(NAME .. ".Signature", "Signature")
function parseSignature(tvb, pinfo, tree)
	local offset = 0
	local signLen = tvb(offset, 2)
	offset = offset + 2
	tree:add(fields.signatureLength, signLen)
	tree:add(fields.signature, tvb(offset, signLen:uint()))
	offset = offset + signLen:uint()
	return offset
end

function initTables()
	-- Cipher Suite Tables.
	cuiteTable[0x0001] = "TLS_RSA_WITH_NULL_MD5"
    cuiteTable[0x0002] = "TLS_RSA_WITH_NULL_SHA"
    cuiteTable[0x0003] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x0004] = "TLS_RSA_WITH_RC4_128_MD5"
    cuiteTable[0x0005] = "TLS_RSA_WITH_RC4_128_SHA"
    cuiteTable[0x0006] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
    cuiteTable[0x0007] = "TLS_RSA_WITH_IDEA_CBC_SHA"
    cuiteTable[0x0008] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0009] = "TLS_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x000a] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x000b] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x000c] = "TLS_DH_DSS_WITH_DES_CBC_SHA"
    cuiteTable[0x000d] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x000e] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x000f] = "TLS_DH_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x0010] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0011] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0012] = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
    cuiteTable[0x0013] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0014] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0015] = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x0016] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0017] = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x0018] = "TLS_DH_anon_WITH_RC4_128_MD5"
    cuiteTable[0x0019] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x001a] = "TLS_DH_anon_WITH_DES_CBC_SHA"
    cuiteTable[0x001b] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x001c] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA"
    cuiteTable[0x001d] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"
    cuiteTable[0x001e] = "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
    cuiteTable[0x001E] = "TLS_KRB5_WITH_DES_CBC_SHA"
    cuiteTable[0x001F] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0020] = "TLS_KRB5_WITH_RC4_128_SHA"
    cuiteTable[0x0021] = "TLS_KRB5_WITH_IDEA_CBC_SHA"
    cuiteTable[0x0022] = "TLS_KRB5_WITH_DES_CBC_MD5"
    cuiteTable[0x0023] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
    cuiteTable[0x0024] = "TLS_KRB5_WITH_RC4_128_MD5"
    cuiteTable[0x0025] = "TLS_KRB5_WITH_IDEA_CBC_MD5"
    cuiteTable[0x0026] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
    cuiteTable[0x0027] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
    cuiteTable[0x0028] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
    cuiteTable[0x0029] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
    cuiteTable[0x002A] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
    cuiteTable[0x002B] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x002C] = "TLS_PSK_WITH_NULL_SHA"
    cuiteTable[0x002D] = "TLS_DHE_PSK_WITH_NULL_SHA"
    cuiteTable[0x002E] = "TLS_RSA_PSK_WITH_NULL_SHA"
    cuiteTable[0x002F] = "TLS_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0030] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0031] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0032] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0033] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0034] = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0036] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0037] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0038] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0039] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x003A] = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
    cuiteTable[0x003B] = "TLS_RSA_WITH_NULL_SHA256"
    cuiteTable[0x003C] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x003D] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x003E] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x003F] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0040] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0041] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0042] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0043] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0044] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0045] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0046] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0060] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"
    cuiteTable[0x0061] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"
    cuiteTable[0x0062] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
    cuiteTable[0x0063] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"
    cuiteTable[0x0064] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"
    cuiteTable[0x0065] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"
    cuiteTable[0x0066] = "TLS_DHE_DSS_WITH_RC4_128_SHA"
    cuiteTable[0x0067] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0068] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x0069] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006A] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006B] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006C] = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x006D] = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x0080] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT"
    cuiteTable[0x0081] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
    cuiteTable[0x0082] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411"
    cuiteTable[0x0083] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411"
    cuiteTable[0x0084] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0085] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0086] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0087] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0088] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0089] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x008A] = "TLS_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x008B] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x008C] = "TLS_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x008D] = "TLS_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x008E] = "TLS_DHE_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x008F] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0090] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0091] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0092] = "TLS_RSA_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x0093] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0094] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0095] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0096] = "TLS_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x0097] = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
    cuiteTable[0x0098] = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x0099] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
    cuiteTable[0x009A] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x009B] = "TLS_DH_anon_WITH_SEED_CBC_SHA"
    cuiteTable[0x009C] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x009D] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x009E] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x009F] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A0] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A1] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A2] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A3] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A4] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A5] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A6] = "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A7] = "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A8] = "TLS_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A9] = "TLS_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AA] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00AB] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AC] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00AD] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AE] = "TLS_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00AF] = "TLS_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B0] = "TLS_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B1] = "TLS_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00B2] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00B3] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B4] = "TLS_DHE_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B5] = "TLS_DHE_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00B6] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00B7] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B8] = "TLS_RSA_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B9] = "TLS_RSA_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00BA] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BB] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BC] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BD] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BE] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BF] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00C0] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C1] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C2] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C3] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C4] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C5] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C6] = "TLS_SM4_GCM_SM3"
    cuiteTable[0x00C7] = "TLS_SM4_CCM_SM3"
    cuiteTable[0x00FF] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
    cuiteTable[0x0A0A] = "Reserved (GREASE)"
    cuiteTable[0x1301] = "TLS_AES_128_GCM_SHA256"
    cuiteTable[0x1302] = "TLS_AES_256_GCM_SHA384"
    cuiteTable[0x1303] = "TLS_CHACHA20_POLY1305_SHA256"
    cuiteTable[0x1304] = "TLS_AES_128_CCM_SHA256"
    cuiteTable[0x1305] = "TLS_AES_128_CCM_8_SHA256"
    cuiteTable[0x1A1A] = "Reserved (GREASE)"
    cuiteTable[0x2A2A] = "Reserved (GREASE)"
    cuiteTable[0x3A3A] = "Reserved (GREASE)"
    cuiteTable[0x4A4A] = "Reserved (GREASE)"
    cuiteTable[0x5600] = "TLS_FALLBACK_SCSV"
    cuiteTable[0x5A5A] = "Reserved (GREASE)"
    cuiteTable[0x6A6A] = "Reserved (GREASE)"
    cuiteTable[0x7A7A] = "Reserved (GREASE)"
    cuiteTable[0x8A8A] = "Reserved (GREASE)"
    cuiteTable[0x9A9A] = "Reserved (GREASE)"
    cuiteTable[0xAAAA] = "Reserved (GREASE)"
    cuiteTable[0xBABA] = "Reserved (GREASE)"
    cuiteTable[0xc001] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
    cuiteTable[0xc002] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
    cuiteTable[0xc003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc006] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
    cuiteTable[0xc007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    cuiteTable[0xc008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc00a] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc00b] = "TLS_ECDH_RSA_WITH_NULL_SHA"
    cuiteTable[0xc00c] = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
    cuiteTable[0xc00d] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc00e] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc00f] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc010] = "TLS_ECDHE_RSA_WITH_NULL_SHA"
    cuiteTable[0xc011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
    cuiteTable[0xc012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc015] = "TLS_ECDH_anon_WITH_NULL_SHA"
    cuiteTable[0xc016] = "TLS_ECDH_anon_WITH_RC4_128_SHA"
    cuiteTable[0xc017] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc018] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc019] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC01A] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01B] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01C] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01D] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC01E] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC01F] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC020] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC021] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC022] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC029] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC02A] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC031] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC032] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC033] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
    cuiteTable[0xC034] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC035] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC036] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC037] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC038] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC039] = "TLS_ECDHE_PSK_WITH_NULL_SHA"
    cuiteTable[0xC03A] = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
    cuiteTable[0xC03B] = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
    cuiteTable[0xC03C] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC03D] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC03E] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC03F] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC040] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC041] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC042] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC043] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC044] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC045] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC046] = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC047] = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC048] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC049] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04A] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04B] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04C] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04D] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04E] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04F] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC050] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC051] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC052] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC053] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC054] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC055] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC056] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC057] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC058] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC059] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05A] = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05B] = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05C] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05D] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05E] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05F] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC060] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC061] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC062] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC063] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC064] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC065] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC066] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC067] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC068] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC069] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC06A] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06B] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC06C] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06D] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC06E] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06F] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC070] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC071] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC072] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC073] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC074] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC075] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC076] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC077] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC078] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC079] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC07A] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07B] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC07C] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07D] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC07E] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07F] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC080] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC081] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC082] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC083] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC084] = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC085] = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC086] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC087] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC088] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC089] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08A] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08B] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08C] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08D] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08E] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08F] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC090] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC091] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC092] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC093] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC094] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC095] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC096] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC097] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC098] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC099] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC09A] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC09B] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC09C] = "TLS_RSA_WITH_AES_128_CCM"
    cuiteTable[0xC09D] = "TLS_RSA_WITH_AES_256_CCM"
    cuiteTable[0xC09E] = "TLS_DHE_RSA_WITH_AES_128_CCM"
    cuiteTable[0xC09F] = "TLS_DHE_RSA_WITH_AES_256_CCM"
    cuiteTable[0xC0A0] = "TLS_RSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A1] = "TLS_RSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0A2] = "TLS_DHE_RSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A3] = "TLS_DHE_RSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0A4] = "TLS_PSK_WITH_AES_128_CCM"
    cuiteTable[0xC0A5] = "TLS_PSK_WITH_AES_256_CCM"
    cuiteTable[0xC0A6] = "TLS_DHE_PSK_WITH_AES_128_CCM"
    cuiteTable[0xC0A7] = "TLS_DHE_PSK_WITH_AES_256_CCM"
    cuiteTable[0xC0A8] = "TLS_PSK_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A9] = "TLS_PSK_WITH_AES_256_CCM_8"
    cuiteTable[0xC0AA] = "TLS_PSK_DHE_WITH_AES_128_CCM_8"
    cuiteTable[0xC0AB] = "TLS_PSK_DHE_WITH_AES_256_CCM_8"
    cuiteTable[0xC0AC] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
    cuiteTable[0xC0AD] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
    cuiteTable[0xC0AE] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0AF] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0B0] = "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC0B1] = "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC0B2] = "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"
    cuiteTable[0xC0B3] = "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"
    cuiteTable[0xC0B4] = "TLS_SHA256_SHA256"
    cuiteTable[0xC0B5] = "TLS_SHA384_SHA384"
    cuiteTable[0xC0FF] = "TLS_ECJPAKE_WITH_AES_128_CCM_8"
    cuiteTable[0xC100] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"
    cuiteTable[0xC101] = "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"
    cuiteTable[0xC102] = "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
    cuiteTable[0xC103] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"
    cuiteTable[0xC104] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"
    cuiteTable[0xC105] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"
    cuiteTable[0xC106] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"
    cuiteTable[0xCACA] = "Reserved (GREASE)"
    cuiteTable[0xCC13] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCC14] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCC15] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCA8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCA9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAA] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAB] = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAC] = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAD] = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAE] = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xD001] = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xD002] = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xD003] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"
    cuiteTable[0xD005] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"
    cuiteTable[0xDADA] = "Reserved (GREASE)"
    cuiteTable[0xE410] = "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE411] = "TLS_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE412] = "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE413] = "TLS_ECDHE_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE414] = "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE415] = "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE416] = "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE417] = "TLS_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE418] = "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE419] = "TLS_ECDHE_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41A] = "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41B] = "TLS_RSA_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41C] = "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41D] = "TLS_DHE_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41E] = "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41F] = "TLS_DHE_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xEAEA] = "Reserved (GREASE)"
    cuiteTable[0xFAFA] = "Reserved (GREASE)"
    cuiteTable[0xfefe] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
    cuiteTable[0xfeff] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xffe0] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xffe1] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
    cuiteTable[0xE001] = "TLS1_CK_ECDHE_WITH_SM1_SM3"
    cuiteTable[0xE003] = "TLS1_CK_ECDHE_WITH_SM1_SM3"
    cuiteTable[0xE005] = "TLS1_CK_ECC_WITH_SM1_SM3"
    cuiteTable[0xE007] = "TLS1_CK_IBC_WITH_SM1_SM3"
    cuiteTable[0xE009] = "TLS1_CK_RSA_WITH_SM1_SM3"
    cuiteTable[0xE00A] = "TLS1_CK_RSA_WITH_SM1_SHA1"
    cuiteTable[0xE011] = "TLS1_CK_ECDHE_WITH_SM4_SM3"
    cuiteTable[0xE013] = "TLS1_CK_ECC_WITH_SM4_SM3"
    cuiteTable[0xE015] = "TLS1_CK_IBSDH_WITH_SM4_SM3"
    cuiteTable[0xE017] = "TLS1_CK_IBC_WITH_SM4_SM3"
    cuiteTable[0xE019] = "TLS1_CK_RSA_WITH_SM4_SM3"
	cuiteTable[0xE01A] = "TLS1_CK_RSA_WITH_SM4_SHA1"


	extenTable[0] = "server_name"
	extenTable[1] = "max_fragment_length"
	extenTable[2] = "client_certificate_url"
	extenTable[3] = "trusted_ca_keys"
	extenTable[4] = "truncated_hmac"
	extenTable[5] = "status_request"
	extenTable[6] = "user_mapping"
	extenTable[7] = "client_authz"
	extenTable[8] = "server_authz"
	extenTable[9] = "cert_type"
	extenTable[10] = "supported_groups"
	extenTable[11] = "ec_point_formats"
	extenTable[12] = "srp"
	extenTable[13] = "signature_algorithms"
	extenTable[14] = "use_srtp"
	extenTable[15] = "heartbeat"
	extenTable[16] = "application_layer_protocol_negotiation"
	extenTable[17] = "status_request_v2"
	extenTable[18] = "signed_certificate_timestamp"
	extenTable[19] = "client_certificate_type"
	extenTable[20] = "server_certificate_type"
	extenTable[21] = "padding"
	extenTable[22] = "encrypt_then_mac"
	extenTable[23] = "extended_master_secret"
	extenTable[24] = "token_binding"
	extenTable[25] = "cached_info"
	extenTable[27] = "compress_certificate"
	extenTable[28] = "record_size_limit"
	extenTable[35] = "session_ticket"
	extenTable[40] = "Reserved (key_share)"
	extenTable[41] = "pre_shared_key"
	extenTable[42] = "early_data"
	extenTable[43] = "supported_versions"
	extenTable[44] = "cookie"
	extenTable[45] = "psk_key_exchange_modes"
	extenTable[46] = "Reserved (ticket_early_data_info)"
	extenTable[47] = "certificate_authorities"
	extenTable[48] = "oid_filters"
	extenTable[49] = "post_handshake_auth"
	extenTable[50] = "signature_algorithms_cert"
	extenTable[51] = "key_share"
	extenTable[53] = "connection_id"
	extenTable[2570] = "Reserved (GREASE)"
	extenTable[6682] = "Reserved (GREASE)"
	extenTable[10794] = "Reserved (GREASE)"
	extenTable[13172] = "next_protocol_negotiation"
	extenTable[14906] = "Reserved (GREASE)"
	extenTable[19018] = "Reserved (GREASE)"
	extenTable[23130] = "Reserved (GREASE)"
	extenTable[27242] = "Reserved (GREASE)"
	extenTable[30031] = "channel_id_old"
	extenTable[30032] = "channel_id"
	extenTable[65281] = "renegotiation_info"
	extenTable[31354] = "Reserved (GREASE)"
	extenTable[35466] = "Reserved (GREASE)"
	extenTable[39578] = "Reserved (GREASE)"
	extenTable[43690] = "Reserved (GREASE)"
	extenTable[47802] = "Reserved (GREASE)"
	extenTable[51914] = "Reserved (GREASE)"
	extenTable[56026] = "Reserved (GREASE)"
	extenTable[60138] = "Reserved (GREASE)"
	extenTable[64250] = "Reserved (GREASE)"
	extenTable[65445] = "quic_transport_parameters"
	extenTable[65486] = "encrypted_server_name"

	-- Compression Methods Table
	compMethod[0] = "null"
	compMethod[1] = "DEFLATE"
	compMethod[64] = "LZS"

	-- Cipher Key Exchange Methods.
	cipherKeyExgMthod[0x0017] = KEX_DH_ANON
    cipherKeyExgMthod[0x0018] = KEX_DH_ANON
    cipherKeyExgMthod[0x0019] = KEX_DH_ANON
    cipherKeyExgMthod[0x001a] = KEX_DH_ANON
    cipherKeyExgMthod[0x001b] = KEX_DH_ANON
    cipherKeyExgMthod[0x0034] = KEX_DH_ANON
    cipherKeyExgMthod[0x003a] = KEX_DH_ANON
    cipherKeyExgMthod[0x0046] = KEX_DH_ANON
    cipherKeyExgMthod[0x006c] = KEX_DH_ANON
    cipherKeyExgMthod[0x006d] = KEX_DH_ANON
    cipherKeyExgMthod[0x0089] = KEX_DH_ANON
    cipherKeyExgMthod[0x009b] = KEX_DH_ANON
    cipherKeyExgMthod[0x00a6] = KEX_DH_ANON
    cipherKeyExgMthod[0x00a7] = KEX_DH_ANON
    cipherKeyExgMthod[0x00bf] = KEX_DH_ANON
    cipherKeyExgMthod[0x00c5] = KEX_DH_ANON
    cipherKeyExgMthod[0xc084] = KEX_DH_ANON
    cipherKeyExgMthod[0xc085] = KEX_DH_ANON
    --    return KEX_DH_ANON;
    cipherKeyExgMthod[0x000b] = KEX_DH_DSS
    cipherKeyExgMthod[0x000c] = KEX_DH_DSS
    cipherKeyExgMthod[0x000d] = KEX_DH_DSS
    cipherKeyExgMthod[0x0030] = KEX_DH_DSS
    cipherKeyExgMthod[0x0036] = KEX_DH_DSS
    cipherKeyExgMthod[0x003e] = KEX_DH_DSS
    cipherKeyExgMthod[0x0042] = KEX_DH_DSS
    cipherKeyExgMthod[0x0068] = KEX_DH_DSS
    cipherKeyExgMthod[0x0085] = KEX_DH_DSS
    cipherKeyExgMthod[0x0097] = KEX_DH_DSS
    cipherKeyExgMthod[0x00a4] = KEX_DH_DSS
    cipherKeyExgMthod[0x00a5] = KEX_DH_DSS
    cipherKeyExgMthod[0x00bb] = KEX_DH_DSS
    cipherKeyExgMthod[0x00c1] = KEX_DH_DSS
    cipherKeyExgMthod[0xc082] = KEX_DH_DSS
    cipherKeyExgMthod[0xc083] = KEX_DH_DSS
    --    return KEX_DH_DSS;
    cipherKeyExgMthod[0x000e] = KEX_DH_RSA
    cipherKeyExgMthod[0x000f] = KEX_DH_RSA
    cipherKeyExgMthod[0x0010] = KEX_DH_RSA
    cipherKeyExgMthod[0x0031] = KEX_DH_RSA
    cipherKeyExgMthod[0x0037] = KEX_DH_RSA
    cipherKeyExgMthod[0x003f] = KEX_DH_RSA
    cipherKeyExgMthod[0x0043] = KEX_DH_RSA
    cipherKeyExgMthod[0x0069] = KEX_DH_RSA
    cipherKeyExgMthod[0x0086] = KEX_DH_RSA
    cipherKeyExgMthod[0x0098] = KEX_DH_RSA
    cipherKeyExgMthod[0x00a0] = KEX_DH_RSA
    cipherKeyExgMthod[0x00a1] = KEX_DH_RSA
    cipherKeyExgMthod[0x00bc] = KEX_DH_RSA
    cipherKeyExgMthod[0x00c2] = KEX_DH_RSA
    cipherKeyExgMthod[0xc07e] = KEX_DH_RSA
    cipherKeyExgMthod[0xc07f] = KEX_DH_RSA
    --    return KEX_DH_RSA;
    cipherKeyExgMthod[0x0011] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0012] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0013] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0032] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0038] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0040] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0044] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0063] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0065] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0066] = KEX_DHE_DSS
    cipherKeyExgMthod[0x006a] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0087] = KEX_DHE_DSS
    cipherKeyExgMthod[0x0099] = KEX_DHE_DSS
    cipherKeyExgMthod[0x00a2] = KEX_DHE_DSS
    cipherKeyExgMthod[0x00a3] = KEX_DHE_DSS
    cipherKeyExgMthod[0x00bd] = KEX_DHE_DSS
    cipherKeyExgMthod[0x00c3] = KEX_DHE_DSS
    cipherKeyExgMthod[0xc080] = KEX_DHE_DSS
    cipherKeyExgMthod[0xc081] = KEX_DHE_DSS
    --    return KEX_DHE_DSS;
    cipherKeyExgMthod[0x002d] = KEX_DHE_PSK
    cipherKeyExgMthod[0x008e] = KEX_DHE_PSK
    cipherKeyExgMthod[0x008f] = KEX_DHE_PSK
    cipherKeyExgMthod[0x0090] = KEX_DHE_PSK
    cipherKeyExgMthod[0x0091] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00aa] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00ab] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00b2] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00b3] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00b4] = KEX_DHE_PSK
    cipherKeyExgMthod[0x00b5] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc090] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc091] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc096] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc097] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc0a6] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc0a7] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc0aa] = KEX_DHE_PSK
    cipherKeyExgMthod[0xc0ab] = KEX_DHE_PSK
    cipherKeyExgMthod[0xccad] = KEX_DHE_PSK
    cipherKeyExgMthod[0xe41c] = KEX_DHE_PSK
    cipherKeyExgMthod[0xe41d] = KEX_DHE_PSK
    --    return KEX_DHE_PSK;
    cipherKeyExgMthod[0x0014] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0015] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0016] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0033] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0039] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0045] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0067] = KEX_DHE_RSA
    cipherKeyExgMthod[0x006b] = KEX_DHE_RSA
    cipherKeyExgMthod[0x0088] = KEX_DHE_RSA
    cipherKeyExgMthod[0x009a] = KEX_DHE_RSA
    cipherKeyExgMthod[0x009e] = KEX_DHE_RSA
    cipherKeyExgMthod[0x009f] = KEX_DHE_RSA
    cipherKeyExgMthod[0x00be] = KEX_DHE_RSA
    cipherKeyExgMthod[0x00c4] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc07c] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc07d] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc09e] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc09f] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc0a2] = KEX_DHE_RSA
    cipherKeyExgMthod[0xc0a3] = KEX_DHE_RSA
    cipherKeyExgMthod[0xccaa] = KEX_DHE_RSA
    cipherKeyExgMthod[0xe41e] = KEX_DHE_RSA
    cipherKeyExgMthod[0xe41f] = KEX_DHE_RSA
    --    return KEX_DHE_RSA;
    cipherKeyExgMthod[0xc015] = KEX_ECDH_ANON
    cipherKeyExgMthod[0xc016] = KEX_ECDH_ANON
    cipherKeyExgMthod[0xc017] = KEX_ECDH_ANON
    cipherKeyExgMthod[0xc018] = KEX_ECDH_ANON
    cipherKeyExgMthod[0xc019] = KEX_ECDH_ANON
    --    return KEX_ECDH_ANON;
    cipherKeyExgMthod[0xc001] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc002] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc003] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc004] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc005] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc025] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc026] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc02d] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc02e] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc074] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc075] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc088] = KEX_ECDH_ECDSA
    cipherKeyExgMthod[0xc089] = KEX_ECDH_ECDSA
    --    return KEX_ECDH_ECDSA;
    cipherKeyExgMthod[0xc00b] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc00c] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc00d] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc00e] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc00f] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc029] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc02a] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc031] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc032] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc078] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc079] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc08c] = KEX_ECDH_RSA
    cipherKeyExgMthod[0xc08d] = KEX_ECDH_RSA
    --    return KEX_ECDH_RSA;
    cipherKeyExgMthod[0xc006] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc007] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc008] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc009] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc00a] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc023] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc024] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc02b] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc02c] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc072] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc073] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc086] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc087] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc0ac] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc0ad] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc0ae] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xc0af] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xcca9] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xe414] = KEX_ECDHE_ECDSA
    cipherKeyExgMthod[0xe415] = KEX_ECDHE_ECDSA
    --    return KEX_ECDHE_ECDSA;
    cipherKeyExgMthod[0xc033] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc034] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc035] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc036] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc037] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc038] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc039] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc03a] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc03b] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc09a] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xc09b] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xccac] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xe418] = KEX_ECDHE_PSK
    cipherKeyExgMthod[0xe419] = KEX_ECDHE_PSK
    --    return KEX_ECDHE_PSK;
    cipherKeyExgMthod[0xc010] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc011] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc012] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc013] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc014] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc027] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc028] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc02f] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc030] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc076] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc077] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc08a] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xc08b] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xcca8] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xe412] = KEX_ECDHE_RSA
    cipherKeyExgMthod[0xe413] = KEX_ECDHE_RSA
    --    return KEX_ECDHE_RSA;
    cipherKeyExgMthod[0x001e] = KEX_KRB5
    cipherKeyExgMthod[0x001f] = KEX_KRB5
    cipherKeyExgMthod[0x0020] = KEX_KRB5
    cipherKeyExgMthod[0x0021] = KEX_KRB5
    cipherKeyExgMthod[0x0022] = KEX_KRB5
    cipherKeyExgMthod[0x0023] = KEX_KRB5
    cipherKeyExgMthod[0x0024] = KEX_KRB5
    cipherKeyExgMthod[0x0025] = KEX_KRB5
    cipherKeyExgMthod[0x0026] = KEX_KRB5
    cipherKeyExgMthod[0x0027] = KEX_KRB5
    cipherKeyExgMthod[0x0028] = KEX_KRB5
    cipherKeyExgMthod[0x0029] = KEX_KRB5
    cipherKeyExgMthod[0x002a] = KEX_KRB5
    cipherKeyExgMthod[0x002b] = KEX_KRB5
    --    return KEX_KRB5;
    cipherKeyExgMthod[0x002c] = KEX_PSK
    cipherKeyExgMthod[0x008a] = KEX_PSK
    cipherKeyExgMthod[0x008b] = KEX_PSK
    cipherKeyExgMthod[0x008c] = KEX_PSK
    cipherKeyExgMthod[0x008d] = KEX_PSK
    cipherKeyExgMthod[0x00a8] = KEX_PSK
    cipherKeyExgMthod[0x00a9] = KEX_PSK
    cipherKeyExgMthod[0x00ae] = KEX_PSK
    cipherKeyExgMthod[0x00af] = KEX_PSK
    cipherKeyExgMthod[0x00b0] = KEX_PSK
    cipherKeyExgMthod[0x00b1] = KEX_PSK
    cipherKeyExgMthod[0xc064] = KEX_PSK
    cipherKeyExgMthod[0xc065] = KEX_PSK
    cipherKeyExgMthod[0xc08e] = KEX_PSK
    cipherKeyExgMthod[0xc08f] = KEX_PSK
    cipherKeyExgMthod[0xc094] = KEX_PSK
    cipherKeyExgMthod[0xc095] = KEX_PSK
    cipherKeyExgMthod[0xc0a4] = KEX_PSK
    cipherKeyExgMthod[0xc0a5] = KEX_PSK
    cipherKeyExgMthod[0xc0a8] = KEX_PSK
    cipherKeyExgMthod[0xc0a9] = KEX_PSK
    cipherKeyExgMthod[0xccab] = KEX_PSK
    cipherKeyExgMthod[0xe416] = KEX_PSK
    cipherKeyExgMthod[0xe417] = KEX_PSK
    --    return KEX_PSK;
    cipherKeyExgMthod[0x0001] = KEX_RSA
    cipherKeyExgMthod[0x0002] = KEX_RSA
    cipherKeyExgMthod[0x0003] = KEX_RSA
    cipherKeyExgMthod[0x0004] = KEX_RSA
    cipherKeyExgMthod[0x0005] = KEX_RSA
    cipherKeyExgMthod[0x0006] = KEX_RSA
    cipherKeyExgMthod[0x0007] = KEX_RSA
    cipherKeyExgMthod[0x0008] = KEX_RSA
    cipherKeyExgMthod[0x0009] = KEX_RSA
    cipherKeyExgMthod[0x000a] = KEX_RSA
    cipherKeyExgMthod[0x002f] = KEX_RSA
    cipherKeyExgMthod[0x0035] = KEX_RSA
    cipherKeyExgMthod[0x003b] = KEX_RSA
    cipherKeyExgMthod[0x003c] = KEX_RSA
    cipherKeyExgMthod[0x003d] = KEX_RSA
    cipherKeyExgMthod[0x0041] = KEX_RSA
    cipherKeyExgMthod[0x0060] = KEX_RSA
    cipherKeyExgMthod[0x0061] = KEX_RSA
    cipherKeyExgMthod[0x0062] = KEX_RSA
    cipherKeyExgMthod[0x0064] = KEX_RSA
    cipherKeyExgMthod[0x0084] = KEX_RSA
    cipherKeyExgMthod[0x0096] = KEX_RSA
    cipherKeyExgMthod[0x009c] = KEX_RSA
    cipherKeyExgMthod[0x009d] = KEX_RSA
    cipherKeyExgMthod[0x00ba] = KEX_RSA
    cipherKeyExgMthod[0x00c0] = KEX_RSA
    cipherKeyExgMthod[0xc07a] = KEX_RSA
    cipherKeyExgMthod[0xc07b] = KEX_RSA
    cipherKeyExgMthod[0xc09c] = KEX_RSA
    cipherKeyExgMthod[0xc09d] = KEX_RSA
    cipherKeyExgMthod[0xc0a0] = KEX_RSA
    cipherKeyExgMthod[0xc0a1] = KEX_RSA
    cipherKeyExgMthod[0xe410] = KEX_RSA
    cipherKeyExgMthod[0xe411] = KEX_RSA
    cipherKeyExgMthod[0xfefe] = KEX_RSA
    cipherKeyExgMthod[0xfeff] = KEX_RSA
    cipherKeyExgMthod[0xffe0] = KEX_RSA
    cipherKeyExgMthod[0xffe1] = KEX_RSA
    --    return KEX_RSA;
    cipherKeyExgMthod[0x002e] = KEX_RSA_PSK
    cipherKeyExgMthod[0x0092] = KEX_RSA_PSK
    cipherKeyExgMthod[0x0093] = KEX_RSA_PSK
    cipherKeyExgMthod[0x0094] = KEX_RSA_PSK
    cipherKeyExgMthod[0x0095] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00ac] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00ad] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00b6] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00b7] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00b8] = KEX_RSA_PSK
    cipherKeyExgMthod[0x00b9] = KEX_RSA_PSK
    cipherKeyExgMthod[0xc092] = KEX_RSA_PSK
    cipherKeyExgMthod[0xc093] = KEX_RSA_PSK
    cipherKeyExgMthod[0xc098] = KEX_RSA_PSK
    cipherKeyExgMthod[0xc099] = KEX_RSA_PSK
    cipherKeyExgMthod[0xccae] = KEX_RSA_PSK
    cipherKeyExgMthod[0xe41a] = KEX_RSA_PSK
    cipherKeyExgMthod[0xe41b] = KEX_RSA_PSK
    --    return KEX_RSA_PSK;
    cipherKeyExgMthod[0xc01a] = KEX_SRP_SHA
    cipherKeyExgMthod[0xc01d] = KEX_SRP_SHA
    cipherKeyExgMthod[0xc020] = KEX_SRP_SHA
    --    return KEX_SRP_SHA;
    cipherKeyExgMthod[0xc01c] = KEX_SRP_SHA_DSS
    cipherKeyExgMthod[0xc01f] = KEX_SRP_SHA_DSS
    cipherKeyExgMthod[0xc022] = KEX_SRP_SHA_DSS
    --    return KEX_SRP_SHA_DSS;
    cipherKeyExgMthod[0xc01b] = KEX_SRP_SHA_RSA
    cipherKeyExgMthod[0xc01e] = KEX_SRP_SHA_RSA
    cipherKeyExgMthod[0xc021] = KEX_SRP_SHA_RSA
    --    return KEX_SRP_SHA_RSA;
    cipherKeyExgMthod[0xc0ff] = KEX_ECJPAKE
	--    return KEX_ECJPAKE;
	
	cipherKeyExgMthod[0xe001] = KEX_ECDHE_ECDSA
	cipherKeyExgMthod[0xe003] = KEX_ECDHE_ECDSA
	cipherKeyExgMthod[0xe011] = KEX_ECDHE_ECDSA
	cipherKeyExgMthod[0xe013] = KEX_ECDHE_ECDSA

	cipherKeyExgMthod[0xe009] = KEX_RSA
	cipherKeyExgMthod[0xe00a] = KEX_RSA
	cipherKeyExgMthod[0xe019] = KEX_RSA
	cipherKeyExgMthod[0xe01a] = KEX_RSA

	cipherKeyExgMthod[0xe005] = KEX_IBSDH
	cipherKeyExgMthod[0xe007] = KEX_IBC
	cipherKeyExgMthod[0xe015] = KEX_IBSDH
	cipherKeyExgMthod[0xe017] = KEX_IBC
end
-- register this dissector
DissectorTable.get("tcp.port"):add(PORT, GMSSL)
