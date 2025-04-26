
rule Trojan_BAT_Jalapeno_NG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 0c 25 17 58 13 0c 11 0b 1e 64 d2 9c } //2
		$a_01_1 = {11 03 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}