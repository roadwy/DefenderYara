
rule Trojan_BAT_LummaC_MBZU_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 71 1a 00 00 01 20 88 00 00 00 61 d2 81 1a 00 00 01 03 50 06 90 01 01 1a 00 00 01 25 71 1a 00 00 01 1f 2e 58 d2 90 00 } //1
		$a_01_1 = {46 72 69 65 6e 64 6c 79 2e 65 78 65 00 4b 74 7a 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}