
rule Trojan_Win64_BumbleBee_SAU_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 0a 48 90 01 03 8b 8f 90 01 04 8b c1 44 90 01 06 41 90 01 02 2d 90 01 04 09 87 90 01 04 8d 41 90 01 01 8b 8f 90 01 04 0f af c8 89 8f 90 01 04 8b 8f 90 01 04 01 8f 90 01 04 48 90 01 06 0f 8c 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}