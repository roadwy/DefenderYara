
rule Trojan_Win64_BumbleBee_HJ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 89 5c 24 90 01 01 44 8b 88 90 01 04 44 2b 4b 90 01 01 44 03 8b 90 01 04 44 8b 80 90 01 04 44 0f af c2 8b 93 90 01 04 33 93 90 01 04 44 89 54 24 90 01 01 81 e2 90 01 04 44 89 4c 24 90 01 01 4c 8b cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}