
rule Trojan_Win64_BumbleBee_SF_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 8b c2 48 31 83 90 01 04 48 8b 43 90 01 01 48 90 01 06 48 01 8b 90 01 04 48 8b 83 90 01 04 8b 88 90 01 04 83 e9 90 01 01 41 90 01 02 74 90 00 } //1
		$a_03_1 = {48 8b 82 48 01 00 00 48 90 01 06 48 0f af c1 48 90 01 06 48 90 01 06 4c 90 01 06 41 90 01 02 48 c7 80 90 01 08 44 90 01 03 0f 82 90 00 } //1
		$a_00_2 = {4b 4a 74 59 6c 71 } //1 KJtYlq
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}