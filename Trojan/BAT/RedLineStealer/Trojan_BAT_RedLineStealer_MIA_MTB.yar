
rule Trojan_BAT_RedLineStealer_MIA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {62 67 66 64 66 67 64 66 2e 65 78 65 } //1 bgfdfgdf.exe
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {47 65 74 48 49 4e 53 54 41 4e 43 45 } //1 GetHINSTANCE
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_9 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_10 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}