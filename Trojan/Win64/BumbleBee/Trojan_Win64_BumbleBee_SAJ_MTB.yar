
rule Trojan_Win64_BumbleBee_SAJ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 83 90 01 04 48 90 01 06 48 90 01 06 44 90 01 03 8b 83 90 01 04 33 83 90 01 04 8b 4b 90 01 01 35 90 01 04 01 83 90 01 04 8b 83 90 01 04 33 43 90 01 01 8b 93 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}