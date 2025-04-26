
rule Trojan_Win32_Guloader_CCHU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 6f 74 64 6f 67 67 65 6e 2e 69 6e 69 } //1 hotdoggen.ini
		$a_01_1 = {4b 61 70 73 65 6a 6c 65 72 5c 73 65 67 6c 65 73 } //1 Kapsejler\segles
		$a_01_2 = {72 65 70 6c 69 67 68 74 2e 69 6e 69 } //1 replight.ini
		$a_01_3 = {4d 75 6e 64 73 74 79 6b 6b 65 74 2e 6d 69 6e } //1 Mundstykket.min
		$a_01_4 = {6f 75 74 66 65 72 72 65 74 2e 75 67 79 } //1 outferret.ugy
		$a_01_5 = {47 72 75 6e 64 73 74 64 73 5c 62 61 74 74 6c 65 64 72 65 73 73 65 74 } //1 Grundstds\battledresset
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}