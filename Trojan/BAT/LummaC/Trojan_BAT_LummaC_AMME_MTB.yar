
rule Trojan_BAT_LummaC_AMME_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 11 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 28 ?? 00 00 06 a5 ?? 00 00 01 61 d2 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}