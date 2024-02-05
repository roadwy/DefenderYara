
rule Trojan_Win64_BumbleBee_SAN_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 83 90 01 04 31 4b 90 01 01 35 90 01 04 01 43 90 01 01 b8 90 01 04 2b 03 01 83 90 00 } //01 00 
		$a_03_1 = {2b c2 2b 43 90 01 01 01 83 90 01 04 8b 83 90 01 04 2d 90 01 04 31 83 90 01 04 49 90 01 06 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}