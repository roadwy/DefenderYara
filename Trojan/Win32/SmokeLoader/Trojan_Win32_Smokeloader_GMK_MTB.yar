
rule Trojan_Win32_Smokeloader_GMK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {32 98 72 16 98 7b 3e 8a fd 01 bb 32 01 ad b6 7b } //0a 00 
		$a_01_1 = {08 3c de 8a e3 00 32 15 e7 84 f0 7e 04 5e 78 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GMK_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 8b 55 90 01 01 d3 e8 03 d7 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 c2 81 3d 90 01 04 03 0b 00 00 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}