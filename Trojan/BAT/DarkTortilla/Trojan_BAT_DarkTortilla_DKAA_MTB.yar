
rule Trojan_BAT_DarkTortilla_DKAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 11 04 75 ?? 00 00 01 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 13 05 1c 13 12 2b 8d 11 05 75 ?? 00 00 01 6f ?? 01 00 0a 13 06 02 73 ?? 01 00 0a 13 07 11 07 75 ?? 00 00 01 11 06 74 ?? 00 00 01 16 73 ?? 01 00 0a 13 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}