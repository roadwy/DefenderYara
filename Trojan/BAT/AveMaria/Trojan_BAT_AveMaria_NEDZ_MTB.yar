
rule Trojan_BAT_AveMaria_NEDZ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 1a 2d 1d 26 07 28 ?? 00 00 0a 0c 08 16 08 8e 69 28 ?? 00 00 0a 08 0d de 25 28 ?? 00 00 0a 2b db 0b 2b e1 26 20 88 13 00 00 28 ?? 00 00 0a de 00 06 13 04 11 04 17 58 0a 06 1b 32 a4 14 2a 09 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}