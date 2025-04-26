
rule Trojan_Win64_CobaltStrike_BMC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 66 62 66 64 68 62 66 64 64 66 62 66 64 6e 68 64 66 68 66 64 2e 66 6c 6c } //1 dfbfdhbfddfbfdnhdfhfd.fll
		$a_01_1 = {65 48 8b 04 25 30 00 00 00 48 8b 40 60 } //1
		$a_01_2 = {48 8b 40 18 } //1
		$a_01_3 = {48 8b 48 10 8a e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}