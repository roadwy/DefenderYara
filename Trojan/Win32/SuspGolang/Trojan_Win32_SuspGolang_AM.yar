
rule Trojan_Win32_SuspGolang_AM{
	meta:
		description = "Trojan:Win32/SuspGolang.AM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 50 72 69 76 73 52 65 71 29 2e } //1 GetPrivsReq).
		$a_81_1 = {57 69 6e 64 6f 77 73 50 72 69 76 69 6c 65 67 65 45 6e 74 72 79 29 2e } //1 WindowsPrivilegeEntry).
		$a_81_2 = {47 65 74 50 72 69 76 73 29 2e } //1 GetPrivs).
		$a_81_3 = {50 69 76 6f 74 53 74 61 72 74 4c 69 73 74 65 6e 65 72 52 65 71 29 2e } //1 PivotStartListenerReq).
		$a_81_4 = {50 69 76 6f 74 53 74 6f 70 4c 69 73 74 65 6e 65 72 52 65 71 29 2e } //1 PivotStopListenerReq).
		$a_81_5 = {29 2e 58 4f 52 4b 65 79 53 74 72 65 61 6d } //1 ).XORKeyStream
		$a_81_6 = {29 2e 44 65 63 72 79 70 74 45 6e 63 50 61 72 74 } //1 ).DecryptEncPart
		$a_81_7 = {29 2e 47 65 74 4b 65 79 53 65 65 64 42 69 74 4c 65 6e 67 74 68 } //1 ).GetKeySeedBitLength
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}