
rule Trojan_Win32_RhadamanthysStealer_EH_MTB{
	meta:
		description = "Trojan:Win32/RhadamanthysStealer.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 03 c5 33 c7 33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04 } //00 00 
	condition:
		any of ($a_*)
 
}