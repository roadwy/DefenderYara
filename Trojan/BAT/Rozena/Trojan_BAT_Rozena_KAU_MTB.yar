
rule Trojan_BAT_Rozena_KAU_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 15 06 11 15 91 1f 1a 61 d2 9c 11 15 17 58 13 15 11 15 06 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}