
rule Trojan_BAT_Heracles_KAI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 11 07 91 20 90 01 01 00 00 00 61 d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}