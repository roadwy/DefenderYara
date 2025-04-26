
rule Trojan_BAT_LummaC_AMAK_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 5d 0d 06 08 91 13 ?? 06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-50] 91 61 d2 81 [0-0f] 11 13 17 58 13 13 11 13 03 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}