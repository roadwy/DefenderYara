
rule Trojan_Win32_Smokeloader_PADR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d 90 01 04 8a 15 90 01 04 30 14 1e 83 ff 0f 75 90 00 } //01 00 
		$a_01_1 = {46 3b f7 7c ca } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_PADR_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.PADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e0 04 89 45 f4 8b 45 e0 01 45 f4 8b 4d ec 8b c7 8b 55 fc d3 e8 03 d7 89 45 f8 8b 45 d8 01 45 f8 8b 45 f8 8d 4d f0 33 c2 8b 55 f4 33 d0 89 55 f4 } //01 00 
		$a_01_1 = {8b 45 f0 c1 e8 05 89 45 f8 8b 55 f4 33 db 8b 45 f8 33 d1 03 45 e4 } //00 00 
	condition:
		any of ($a_*)
 
}