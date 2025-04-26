
rule Trojan_BAT_Jalapeno_ARAX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 18 07 11 18 93 66 d1 9d 11 18 17 58 13 18 11 18 07 8e 69 32 e9 } //2
		$a_01_1 = {07 11 12 07 11 12 93 66 d1 9d 11 12 17 58 13 12 11 12 07 8e 69 32 e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}