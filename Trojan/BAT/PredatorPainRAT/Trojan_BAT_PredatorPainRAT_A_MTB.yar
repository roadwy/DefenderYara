
rule Trojan_BAT_PredatorPainRAT_A_MTB{
	meta:
		description = "Trojan:BAT/PredatorPainRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 06 1a 58 91 06 28 ?? 00 00 06 61 d2 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}