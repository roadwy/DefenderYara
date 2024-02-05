
rule Trojan_Win64_BumbleBee_SAF_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b c8 8b 05 90 01 04 05 90 01 04 44 90 01 06 33 c8 90 00 } //01 00 
		$a_03_1 = {0f af c1 8b 0d 90 01 04 33 ca 89 05 90 01 04 8b 05 90 01 04 05 90 01 04 03 c8 b8 90 01 04 2b 05 90 01 04 01 05 90 01 04 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}