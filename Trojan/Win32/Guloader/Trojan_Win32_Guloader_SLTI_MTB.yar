
rule Trojan_Win32_Guloader_SLTI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 00 65 00 6b 00 74 00 6f 00 72 00 61 00 74 00 65 00 72 00 6e 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //2 Lektoraternes.txt
		$a_01_1 = {61 00 64 00 67 00 61 00 6e 00 67 00 73 00 6b 00 75 00 72 00 73 00 75 00 73 00 2e 00 74 00 78 00 74 00 } //2 adgangskursus.txt
		$a_01_2 = {66 00 6f 00 72 00 61 00 6e 00 64 00 72 00 69 00 6e 00 67 00 73 00 75 00 76 00 69 00 6c 00 6c 00 69 00 67 00 2e 00 62 00 75 00 72 00 } //2 forandringsuvillig.bur
		$a_01_3 = {73 00 63 00 68 00 69 00 7a 00 6f 00 6e 00 65 00 75 00 72 00 61 00 2e 00 6a 00 70 00 67 00 } //2 schizoneura.jpg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}