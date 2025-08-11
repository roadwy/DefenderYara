
rule Trojan_BAT_DarkTortilla_MTS_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 20 80 00 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 19 6f ?? 00 00 0a 00 07 03 6f ?? 00 00 0a 00 07 03 6f ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 0c 02 73 92 00 00 0a 0d 09 08 16 73 93 00 00 0a 13 04 11 04 73 94 00 00 0a 13 05 11 05 02 8e 69 6f ?? 00 00 0a 0a de 52 00 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}