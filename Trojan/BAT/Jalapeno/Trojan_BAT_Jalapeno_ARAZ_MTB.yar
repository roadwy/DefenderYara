
rule Trojan_BAT_Jalapeno_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 02 06 91 08 08 11 04 84 95 08 11 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 18 38 78 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}