
rule Trojan_BAT_AveMaria_NECU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? 00 00 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de 07 28 ?? 00 00 0a 0d 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}