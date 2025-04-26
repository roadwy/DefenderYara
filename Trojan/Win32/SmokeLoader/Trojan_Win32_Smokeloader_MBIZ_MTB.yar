
rule Trojan_Win32_Smokeloader_MBIZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 de 33 d8 2b fb 8b d7 c1 e2 04 89 54 24 14 8b 44 24 2c 01 44 24 14 } //1
		$a_01_1 = {53 00 6f 00 72 00 75 00 78 00 75 00 74 00 61 00 67 00 65 00 62 00 75 00 62 00 20 00 78 00 75 00 67 00 69 00 68 00 69 00 66 00 65 00 68 00 75 00 66 00 75 00 77 00 75 00 20 00 6d 00 61 00 6e 00 65 00 74 00 61 00 78 00 6f 00 73 00 65 00 72 00 20 00 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}