
rule Trojan_Win64_BumbleBee_ZC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 49 0b 8c 24 40 01 00 00 48 03 c8 49 8b 84 24 98 03 00 00 49 03 84 24 d0 04 00 00 49 33 84 24 30 03 00 00 49 33 04 24 49 89 84 24 30 03 00 00 49 89 8c 24 70 04 00 00 8b 4d ff } //1
		$a_01_1 = {45 50 54 73 73 77 77 69 52 4a } //1 EPTsswwiRJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}