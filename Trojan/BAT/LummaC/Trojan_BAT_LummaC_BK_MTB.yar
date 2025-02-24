
rule Trojan_BAT_LummaC_BK_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 2b 11 2d 91 11 2b 11 2e 91 58 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 32 } //3
		$a_03_1 = {01 25 47 11 34 16 6f ?? 00 00 0a 61 d2 52 20 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}