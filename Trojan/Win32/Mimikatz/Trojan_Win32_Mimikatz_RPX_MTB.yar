
rule Trojan_Win32_Mimikatz_RPX_MTB{
	meta:
		description = "Trojan:Win32/Mimikatz.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 00 70 00 64 00 61 00 74 00 65 00 73 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 67 00 61 00 } //1 updates.microsoftupdatesoftware.ga
		$a_01_1 = {70 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 73 00 2f 00 43 00 6c 00 61 00 73 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 picturess/Class.dll
		$a_01_2 = {38 37 2e 32 35 31 2e 6c 6f 67 } //1 87.251.log
		$a_01_3 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //1 urlmon.dll
		$a_01_4 = {45 6e 61 62 6c 65 57 69 6e 64 6f 77 } //1 EnableWindow
		$a_01_5 = {55 52 4c 4f 70 65 6e 42 6c 6f 63 6b 69 6e 67 53 74 72 65 61 6d 57 } //1 URLOpenBlockingStreamW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}