
rule Trojan_Win32_MarsStealer_AMS_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 03 4c 24 90 01 01 8b d0 c1 e2 04 03 54 24 90 01 01 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04 90 00 } //01 00 
		$a_03_1 = {52 6a 00 6a 00 6a 00 ff 15 90 01 04 8b f7 c1 ee 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}