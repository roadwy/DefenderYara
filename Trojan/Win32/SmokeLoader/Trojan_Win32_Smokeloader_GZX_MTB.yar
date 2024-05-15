
rule Trojan_Win32_Smokeloader_GZX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 8b c7 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 55 90 01 01 8d 04 3e 33 d0 81 3d 90 01 04 03 0b 00 00 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}