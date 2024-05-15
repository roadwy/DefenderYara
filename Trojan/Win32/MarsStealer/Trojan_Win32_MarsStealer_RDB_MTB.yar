
rule Trojan_Win32_MarsStealer_RDB_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 89 45 f0 8b 4d e4 8b c7 d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f0 31 45 fc 8b 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}