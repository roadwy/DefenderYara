
rule Trojan_BAT_LummaC_ALU_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 16 13 04 2b 27 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 2e 05 09 17 58 2b 01 16 0d 11 04 17 58 13 04 11 04 02 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_ALU_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 00 77 96 6a ?? ?? ?? ?? ?? 95 bb d7 2a a1 f5 1d 92 e0 e4 13 f1 e4 05 07 84 1c 05 ed 19 } //2
		$a_01_1 = {59 00 76 00 6f 00 6e 00 6e 00 65 00 47 00 72 00 61 00 63 00 65 00 45 00 6c 00 65 00 61 00 6e 00 6f 00 72 00 } //1 YvonneGraceEleanor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_LummaC_ALU_MTB_3{
	meta:
		description = "Trojan:BAT/LummaC.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 } //2
		$a_03_1 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 66 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}