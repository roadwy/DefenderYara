
rule Trojan_BAT_Rozena_GPAR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? 00 00 0a 02 07 17 58 02 8e 69 5d } //8
	condition:
		((#a_03_0  & 1)*8) >=8
 
}