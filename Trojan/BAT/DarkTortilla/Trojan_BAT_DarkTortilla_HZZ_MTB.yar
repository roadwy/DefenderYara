
rule Trojan_BAT_DarkTortilla_HZZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.HZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 14 fe 03 13 04 11 04 39 82 00 00 00 09 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 00 02 73 67 00 00 0a 13 05 00 11 05 09 6f ?? 00 00 0a 16 73 00 01 00 0a 13 06 00 11 06 73 01 01 00 0a 13 07 11 07 02 8e 69 6f 02 01 00 0a 0c de 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}