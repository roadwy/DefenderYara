
rule Trojan_Win32_Vidar_BAS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 03 45 90 01 01 89 45 f8 8b 45 e4 31 45 fc 8b 45 fc 89 45 e8 89 75 f0 8b 45 e8 89 45 f0 8b 45 f8 31 45 f0 8b 45 f0 81 45 ec 90 01 04 2b f8 ff 4d dc 89 45 fc 89 7d e8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}