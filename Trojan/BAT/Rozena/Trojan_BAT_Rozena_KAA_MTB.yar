
rule Trojan_BAT_Rozena_KAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 17 08 11 17 91 20 90 01 01 00 00 00 61 d2 9c 00 11 17 17 58 13 17 11 17 08 8e 69 fe 04 13 18 11 18 2d dc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}