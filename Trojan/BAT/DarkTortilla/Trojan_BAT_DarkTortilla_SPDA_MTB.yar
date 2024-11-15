
rule Trojan_BAT_DarkTortilla_SPDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SPDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 14 0d 14 13 04 14 13 05 14 13 06 00 28 ?? 00 00 0a 13 04 11 04 14 fe 03 13 07 11 07 2c 2a 11 04 08 6f ?? 00 00 0a 00 11 04 08 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? 00 00 0a 0a de 53 00 de 4b } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}