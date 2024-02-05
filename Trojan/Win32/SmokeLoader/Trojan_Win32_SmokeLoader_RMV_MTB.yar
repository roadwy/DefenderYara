
rule Trojan_Win32_SmokeLoader_RMV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4c 24 90 01 01 31 4c 24 90 01 01 03 c3 81 3d 90 01 08 89 44 24 90 01 01 75 90 01 01 55 55 55 55 ff 15 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}