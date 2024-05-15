
rule Trojan_Win64_BumbleBee_TK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.TK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c9 0f af c1 89 05 90 01 04 b8 90 01 04 41 2b 42 90 01 01 41 01 42 90 01 01 48 8b 0d 90 01 04 8b 81 90 01 04 29 81 90 01 04 8b 0d 90 01 04 8b 05 90 01 04 35 90 01 04 0f af c8 8b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}