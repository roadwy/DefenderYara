
rule Trojan_Win64_BumbleBee_JH_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.JH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 ff 43 90 01 01 48 8b 05 90 01 04 8b 88 90 01 04 ff c9 01 8b 90 01 04 48 8b 05 90 01 04 8b 48 90 01 01 33 8b 90 01 04 83 e9 90 01 01 09 8b 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}