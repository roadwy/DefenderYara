
rule Trojan_BAT_Zusy_SWA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 03 16 03 8e 69 6f 14 00 00 0a 00 11 05 6f 15 00 00 0a 00 00 de 14 11 05 14 fe 01 13 07 11 07 2d 08 11 05 6f 16 00 00 0a 00 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}