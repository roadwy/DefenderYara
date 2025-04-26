
rule Trojan_Win32_SuspGolang_LY{
	meta:
		description = "Trojan:Win32/SuspGolang.LY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {57 47 53 6f 63 6b 73 53 65 72 76 65 72 29 2e } //1 WGSocksServer).
		$a_81_1 = {57 47 53 6f 63 6b 73 53 65 72 76 65 72 73 29 2e } //1 WGSocksServers).
		$a_81_2 = {57 47 54 43 50 46 6f 72 77 61 72 64 65 72 73 29 2e } //1 WGTCPForwarders).
		$a_81_3 = {52 65 63 6f 6e 66 69 67 75 72 65 52 65 71 29 2e } //1 ReconfigureReq).
		$a_81_4 = {52 65 63 6f 6e 66 69 67 75 72 65 29 2e } //1 Reconfigure).
		$a_81_5 = {50 6f 6c 6c 49 6e 74 65 72 76 61 6c 52 65 71 29 2e } //1 PollIntervalReq).
		$a_81_6 = {29 2e 4c 6f 63 61 6c 41 64 64 72 } //1 ).LocalAddr
		$a_81_7 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //1 ).RemoteAddr
		$a_81_8 = {29 2e 53 65 74 44 65 61 64 6c 69 6e 65 } //1 ).SetDeadline
		$a_81_9 = {29 2e 53 65 74 52 65 61 64 44 65 61 64 6c 69 6e 65 } //1 ).SetReadDeadline
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}