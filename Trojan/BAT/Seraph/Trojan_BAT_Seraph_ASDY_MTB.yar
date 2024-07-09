
rule Trojan_BAT_Seraph_ASDY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 14 0d 2b 0c 00 28 ?? 00 00 06 0d de 03 26 de 00 09 2c f1 73 ?? 00 00 0a 13 04 09 73 ?? 00 00 0a 13 05 11 05 08 16 73 ?? 00 00 0a 13 06 11 06 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0a de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}