
rule Trojan_Win32_SmokeLoader_ONG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ONG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {d3 ea 03 c7 89 45 90 01 01 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 31 55 90 01 01 89 35 90 01 04 8b 45 90 01 01 89 45 e4 8b 45 90 01 01 29 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}