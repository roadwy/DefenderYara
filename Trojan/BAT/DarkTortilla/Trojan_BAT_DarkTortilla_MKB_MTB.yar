
rule Trojan_BAT_DarkTortilla_MKB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 14 fe 03 13 06 11 06 2c 31 09 07 6f ?? 01 00 0a 6f ?? 00 00 0a 00 09 07 6f ?? 01 00 0a 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 01 00 0a 0a de 51 00 de 49 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}