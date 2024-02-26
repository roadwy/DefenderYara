
rule Trojan_Win32_SmokeLoader_K_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d 90 01 04 21 01 00 00 75 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}