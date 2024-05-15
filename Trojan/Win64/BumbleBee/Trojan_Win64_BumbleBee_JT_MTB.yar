
rule Trojan_Win64_BumbleBee_JT_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 48 8b 05 90 01 04 ff 80 90 01 04 b8 90 01 04 8b 8b 90 01 04 33 4b 90 01 01 2b c1 01 83 90 01 04 8b 83 90 00 } //01 00 
		$a_03_1 = {0f af c8 89 8a 90 01 04 48 8b 0d 90 01 04 8b 81 90 01 04 33 83 90 01 04 2d 90 01 04 09 41 90 01 01 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}