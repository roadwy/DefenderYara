
rule Trojan_Win32_SmokeLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 83 65 f0 00 8b 45 e8 01 45 f0 8b 45 e4 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}