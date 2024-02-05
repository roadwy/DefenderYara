
rule Trojan_Win32_Formbook_PG_MTB{
	meta:
		description = "Trojan:Win32/Formbook.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 28 88 44 24 90 01 01 8b c1 0f af c6 0f af c7 8b d8 89 44 24 90 01 01 2b da 0f af d9 0f af df e8 90 01 04 0b c2 59 74 08 ff 05 90 01 03 00 eb 06 ff 05 90 01 03 00 30 5c 24 90 00 } //01 00 
		$a_02_1 = {85 ff 0f b6 44 24 90 01 01 8b f3 0f b6 ca 0f 45 c8 8b 44 24 90 01 01 0f af c7 88 0c 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}