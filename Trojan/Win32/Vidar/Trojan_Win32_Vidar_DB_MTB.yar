
rule Trojan_Win32_Vidar_DB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 89 18 6a 90 01 01 e8 90 01 04 8b 5d c8 03 5d a0 2b d8 6a 90 01 01 e8 90 01 04 03 d8 8b 45 d8 31 18 6a 90 01 01 e8 90 01 04 bb 04 00 00 00 2b d8 6a 90 01 01 e8 90 01 04 03 d8 01 5d ec 83 45 d8 04 8b 45 ec 3b 45 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}