
rule Trojan_BAT_ClipBanker_MC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {6a 67 73 64 66 73 61 73 64 73 } //1 jgsdfsasds
		$a_01_1 = {44 69 73 63 6f 72 64 20 4c 69 6e 6b 20 3a 20 20 76 31 2e 30 2e 30 2d 63 75 73 74 6f 6d } //1 Discord Link :  v1.0.0-custom
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_7 = {47 65 74 48 49 4e 53 54 41 4e 43 45 } //1 GetHINSTANCE
		$a_01_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_9 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}