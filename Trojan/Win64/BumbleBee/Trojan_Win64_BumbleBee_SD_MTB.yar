
rule Trojan_Win64_BumbleBee_SD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 86 b8 02 00 00 35 90 01 04 44 0f af f8 49 63 cf 48 8b c1 49 0f af 86 90 01 04 48 3b c8 0f 86 90 01 04 41 8b be 90 00 } //01 00 
		$a_03_1 = {8b 94 24 c0 00 00 00 41 33 8e 90 01 04 44 0f af f9 49 8b 8e 90 01 04 ff c2 48 81 c1 90 01 04 48 63 c2 49 23 8e 90 01 04 89 94 24 90 01 04 48 3b c1 0f 85 90 00 } //01 00 
		$a_00_2 = {72 65 67 74 61 73 6b } //00 00 
	condition:
		any of ($a_*)
 
}