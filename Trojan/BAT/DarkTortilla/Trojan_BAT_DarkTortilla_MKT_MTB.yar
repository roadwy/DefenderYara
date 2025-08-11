
rule Trojan_BAT_DarkTortilla_MKT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 50 28 74 00 00 2b 0b 12 01 28 a6 02 00 0a 18 8d 06 00 00 01 25 16 09 8c 60 00 00 01 a2 25 17 03 50 28 ?? 00 00 2b 0b 12 01 28 a6 02 00 0a 17 8d 06 00 00 01 25 16 09 8c 60 00 00 01 a2 14 28 d3 01 00 0a 1f 15 8c 60 00 00 01 28 ?? 02 00 0a a2 14 16 17 28 ?? 02 00 0a 00 09 17 d6 0d 09 08 31 9e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}