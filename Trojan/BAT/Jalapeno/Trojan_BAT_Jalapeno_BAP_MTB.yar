
rule Trojan_BAT_Jalapeno_BAP_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 07 91 06 07 06 8e 69 5d 91 61 20 aa 00 00 00 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}