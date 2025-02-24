
rule Trojan_BAT_LummaC_AMDC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 30 8f ?? 00 00 01 25 47 11 33 16 6f ?? 00 00 0a 61 d2 52 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}