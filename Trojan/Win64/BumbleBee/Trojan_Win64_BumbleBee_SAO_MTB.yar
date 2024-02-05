
rule Trojan_Win64_BumbleBee_SAO_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 11 48 90 01 03 8b 83 90 01 04 01 43 90 01 01 8b 43 90 01 01 83 e8 90 01 01 31 83 90 01 04 48 90 01 06 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}