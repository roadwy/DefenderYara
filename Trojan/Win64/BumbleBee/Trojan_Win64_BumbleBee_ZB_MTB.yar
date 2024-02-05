
rule Trojan_Win64_BumbleBee_ZB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0c 02 33 4b 90 01 01 48 8b 83 90 01 04 89 0c 02 48 83 c2 04 8b 05 90 01 04 01 05 90 01 04 48 8b 05 90 01 04 8b 88 90 01 04 81 e9 90 01 04 31 8b 90 01 04 48 81 fa 90 01 04 7c 90 0a 60 00 48 8b 05 90 01 04 8b 8b 90 01 04 0f af 48 90 01 01 89 8b 90 01 04 48 8b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}