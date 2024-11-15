
rule Trojan_BAT_Rozena_SMDA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SMDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 11 05 11 06 91 1f 7a 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 3f e1 ff ff ff } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}