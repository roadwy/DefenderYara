
rule Trojan_Win64_BumbleBee_SAR_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 0f b6 c9 48 90 01 04 0f b6 4c 0a 02 48 90 01 04 0f b6 04 02 33 c1 48 90 01 04 48 90 01 04 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}