
rule Trojan_BAT_LummaC_GTM_MTB{
	meta:
		description = "Trojan:BAT/LummaC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 08 28 ?? 15 00 06 11 05 09 28 ?? 15 00 06 11 04 11 05 6f ?? 09 00 0a 17 73 ?? ?? ?? 0a 13 06 11 06 07 16 07 8e 69 6f ?? 08 00 0a 11 06 28 ?? 15 00 06 11 04 6f ?? 09 00 0a 28 ?? 09 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}