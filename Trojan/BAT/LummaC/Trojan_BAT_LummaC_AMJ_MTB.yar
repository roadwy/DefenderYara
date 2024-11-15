
rule Trojan_BAT_LummaC_AMJ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 26 16 13 ?? 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 13 ?? 03 11 ?? 91 13 ?? 06 11 ?? 91 13 ?? 28 ?? 00 00 0a 11 ?? 11 ?? 61 d2 13 } //4
		$a_03_1 = {6e 5b 6d 13 [0-14] 6e 58 6d 13 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}