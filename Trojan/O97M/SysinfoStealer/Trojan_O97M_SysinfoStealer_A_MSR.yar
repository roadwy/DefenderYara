
rule Trojan_O97M_SysinfoStealer_A_MSR{
	meta:
		description = "Trojan:O97M/SysinfoStealer.A!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 48 74 74 70 52 65 71 2e 53 65 6e 64 } //1 WinHttpReq.Send
		$a_00_1 = {77 69 6e 4d 67 6d 74 73 2e 45 78 65 63 51 75 65 72 79 28 42 61 73 65 36 34 44 65 63 6f 64 65 53 74 72 69 6e 67 } //1 winMgmts.ExecQuery(Base64DecodeString
		$a_00_2 = {42 61 73 65 36 34 45 6e 63 6f 64 65 53 74 72 69 6e 67 28 47 65 74 44 6f 63 4e 61 6d 65 20 26 20 22 7c 22 20 26 20 47 65 74 43 6f 6d 70 75 74 65 72 49 6e 66 6f 20 26 20 22 7c 22 20 26 20 47 65 74 4f 53 49 6e 66 6f 20 26 20 22 7c 22 20 26 20 47 65 74 41 56 20 26 20 22 7c 22 20 26 20 47 65 74 50 72 6f 63 29 } //2 Base64EncodeString(GetDocName & "|" & GetComputerInfo & "|" & GetOSInfo & "|" & GetAV & "|" & GetProc)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}