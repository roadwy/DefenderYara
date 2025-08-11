
rule Trojan_BAT_DarkTortilla_MZV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0b 11 0b 45 07 00 00 00 5d 00 00 00 5d 00 00 00 00 00 00 00 35 00 00 00 00 00 00 00 35 00 00 00 00 00 00 00 09 75 27 00 00 01 08 74 02 01 00 01 1f 20 6f ?? 03 00 0a 6f ?? 03 00 0a 09 75 27 00 00 01 08 74 02 01 00 01 1f 10 6f ?? 03 00 0a 6f ?? 03 00 0a 1b 13 0b 2b a8 09 75 27 00 00 01 09 74 27 00 00 01 6f ?? 03 00 0a 09 74 27 00 00 01 6f ?? 03 00 0a 6f ?? 03 00 0a 13 04 17 13 0b 2b 80 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}