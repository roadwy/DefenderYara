
rule Trojan_Win32_SmokeLoader_PADN_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c2 2b f8 8b c7 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f8 8b 45 f4 8b f7 d3 ee 03 c7 89 45 e8 03 75 d4 8b 45 e8 31 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}