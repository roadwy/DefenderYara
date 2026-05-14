
rule Trojan_BAT_Jalapeno_GPAX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 17 fe 01 16 fe 01 0c 08 2d 10 02 06 02 06 91 17 07 1f 1f 5f 62 60 d2 9c 2b 0f 02 06 02 06 91 17 07 1f 1f 5f 62 66 5f d2 9c } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}