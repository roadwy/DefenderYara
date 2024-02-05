
rule Trojan_Win32_SmokeLoader_AXX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 44 24 90 01 01 33 44 24 90 01 01 33 c8 51 8b c6 89 4c 24 90 01 01 e8 90 01 04 8b f0 8d 44 24 90 01 01 89 74 90 01 01 24 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}