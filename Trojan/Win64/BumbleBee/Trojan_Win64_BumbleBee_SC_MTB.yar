
rule Trojan_Win64_BumbleBee_SC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 43 08 48 81 f1 90 01 04 48 89 48 90 01 01 48 8b 43 90 01 01 4c 90 01 06 4c 90 01 06 48 90 01 06 48 90 01 06 41 90 01 03 41 90 01 03 8b 8b 90 01 04 81 e1 90 01 04 7d 90 00 } //01 00 
		$a_03_1 = {44 8b 04 88 48 90 01 06 44 03 ce 48 90 01 06 44 01 04 88 44 3b 8b 90 01 04 0f 8c 90 00 } //01 00 
		$a_00_2 = {48 51 4c 51 79 41 4f 54 66 7a } //00 00  HQLQyAOTfz
	condition:
		any of ($a_*)
 
}