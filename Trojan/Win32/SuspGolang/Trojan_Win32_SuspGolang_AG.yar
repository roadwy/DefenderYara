
rule Trojan_Win32_SuspGolang_AG{
	meta:
		description = "Trojan:Win32/SuspGolang.AG,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {57 47 53 6f 63 6b 73 53 74 6f 70 52 65 71 29 2e } //1 WGSocksStopReq).
		$a_81_1 = {57 47 54 43 50 46 6f 72 77 61 72 64 65 72 73 52 65 71 29 2e } //1 WGTCPForwardersReq).
		$a_81_2 = {57 47 53 6f 63 6b 73 53 65 72 76 65 72 73 52 65 71 29 2e } //1 WGSocksServersReq).
		$a_81_3 = {57 47 54 43 50 46 6f 72 77 61 72 64 65 72 29 2e } //1 WGTCPForwarder).
		$a_81_4 = {53 65 72 76 69 63 65 49 6e 66 6f 52 65 71 29 2e } //1 ServiceInfoReq).
		$a_81_5 = {53 74 6f 70 53 65 72 76 69 63 65 52 65 71 29 2e } //1 StopServiceReq).
		$a_81_6 = {52 65 6d 6f 76 65 53 65 72 76 69 63 65 52 65 71 29 2e } //1 RemoveServiceReq).
		$a_81_7 = {42 61 63 6b 64 6f 6f 72 52 65 71 29 2e } //1 BackdoorReq).
		$a_81_8 = {29 2e 53 65 74 55 6e 69 66 6f 72 6d 42 79 74 65 73 } //1 ).SetUniformBytes
		$a_81_9 = {29 2e 53 65 74 43 61 6e 6f 6e 69 63 61 6c 42 79 74 65 73 } //1 ).SetCanonicalBytes
		$a_81_10 = {29 2e 53 65 74 42 79 74 65 73 57 69 74 68 43 6c 61 6d 70 69 6e 67 } //1 ).SetBytesWithClamping
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}