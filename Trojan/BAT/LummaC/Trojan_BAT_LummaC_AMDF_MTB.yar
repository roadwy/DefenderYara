
rule Trojan_BAT_LummaC_AMDF_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 47 11 ?? 16 6f ?? 00 00 0a 61 d2 52 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}