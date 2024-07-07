
rule Trojan_BAT_Stealer_AB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 07 25 1a 58 13 07 4b 11 07 25 1a 58 13 07 4b 5a 13 11 11 11 20 90 01 04 33 2d 08 07 2d 07 11 07 1a 58 4b 2b 08 11 07 19 d3 1a 5a 58 4b e0 58 13 05 07 2d 05 11 07 4b 2b 08 11 07 18 d3 1a 5a 58 4b 18 64 13 06 2b 5a 11 11 2c 56 08 07 2d 07 11 07 1a 58 4b 2b 08 11 07 19 d3 1a 5a 58 4b e0 58 13 12 11 07 18 d3 1a 5a 58 4b 18 64 13 13 16 13 14 2b 28 90 00 } //1
		$a_01_1 = {51 6a 41 49 67 77 53 65 } //1 QjAIgwSe
		$a_01_2 = {7a 6b 76 56 68 73 46 } //1 zkvVhsF
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}