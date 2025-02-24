
rule Trojan_BAT_LummaC_AMDG_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 47 11 ?? 16 6f ?? 00 00 0a 61 d2 52 11 ?? 17 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}