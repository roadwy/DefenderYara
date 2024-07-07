
rule Trojan_Win64_CobaltStrike_CPI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 24 48 8b 4c 24 28 0f b6 04 01 89 44 24 34 48 63 4c 24 24 33 d2 48 8b c1 b9 0a 00 00 00 48 f7 f1 48 8b c2 8b 4c 24 34 33 4c 84 68 8b c1 48 63 4c 24 24 48 8b 54 24 28 88 04 0a } //1
		$a_03_1 = {48 63 44 24 20 48 8b 4c 24 28 0f b6 04 01 89 44 24 30 48 63 4c 24 20 33 d2 48 8b c1 b9 90 01 04 48 f7 f1 48 8b c2 8b 4c 24 30 33 4c 84 40 8b c1 48 63 4c 24 20 48 8b 54 24 28 88 04 0a 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}