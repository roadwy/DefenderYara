
rule Trojan_BAT_Jalapeno_BAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 11 05 94 58 08 11 05 94 58 20 00 01 00 00 5d 13 04 06 11 05 94 13 06 06 11 05 06 11 04 94 9e 06 11 04 11 06 9e 11 05 17 58 13 05 11 05 20 00 01 00 00 32 c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}