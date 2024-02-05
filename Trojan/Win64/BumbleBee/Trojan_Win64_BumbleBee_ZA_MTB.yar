
rule Trojan_Win64_BumbleBee_ZA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 90 01 01 48 8b 0d 90 01 04 8b 15 90 01 04 8b 04 81 33 c2 48 63 4c 24 90 01 01 48 8b 94 24 90 01 04 48 8b 92 90 01 04 89 04 8a b8 90 01 04 48 6b c0 90 01 01 48 8d 0d 90 01 04 48 8b 94 24 90 01 04 8b 52 90 01 01 81 ea 90 01 04 8b 04 01 2b c2 b9 90 01 04 48 6b c9 90 01 01 48 8d 15 90 01 04 89 04 0a b8 90 01 04 48 6b c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}