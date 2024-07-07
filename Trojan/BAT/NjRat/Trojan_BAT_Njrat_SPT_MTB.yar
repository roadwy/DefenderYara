
rule Trojan_BAT_Njrat_SPT_MTB{
	meta:
		description = "Trojan:BAT/Njrat.SPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 14 fe 01 16 fe 01 2d 02 de 51 07 6f 90 01 03 0a d4 8d 13 00 00 01 0c 07 08 16 08 8e 69 6f 90 01 03 0a 26 08 28 90 01 03 0a 72 13 00 00 70 6f 90 01 03 0a 28 01 00 00 06 0c 08 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}