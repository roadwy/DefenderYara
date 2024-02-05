
rule Trojan_Win32_SmokeLoader_AXB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 c1 ee 90 01 01 03 74 24 90 01 01 81 3d 90 01 08 75 90 01 01 ff 15 90 01 04 8b 44 24 90 01 01 33 c6 89 44 24 90 01 01 50 8b c3 e8 90 01 04 8b d8 8d 44 24 90 01 01 89 5c 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}