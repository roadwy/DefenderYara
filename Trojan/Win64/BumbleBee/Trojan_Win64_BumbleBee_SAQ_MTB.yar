
rule Trojan_Win64_BumbleBee_SAQ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c6 44 33 e0 69 c5 90 01 04 48 90 01 02 41 90 01 02 33 43 90 01 01 48 90 01 03 2b e8 8b 43 90 00 } //01 00 
		$a_03_1 = {8b cf 0f af 83 90 01 04 33 cd 23 4b 90 01 01 41 90 01 03 4c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}