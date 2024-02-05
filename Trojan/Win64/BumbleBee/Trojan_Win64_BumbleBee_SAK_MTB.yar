
rule Trojan_Win64_BumbleBee_SAK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 43 90 01 01 8b 43 90 01 01 2b 43 90 01 01 48 90 01 03 05 90 01 04 01 83 90 01 04 8b 43 90 01 01 2b 83 90 01 04 35 90 01 04 29 43 90 01 01 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}