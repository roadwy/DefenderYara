
rule Trojan_BAT_DarkTortilla_HQZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.HQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 1f 18 8c 63 00 00 01 6f ?? 00 00 0a 00 06 73 c0 00 00 0a 6f ?? 00 00 0a 00 16 0b 09 06 16 6f ?? 00 00 0a 14 72 12 4f 0c 70 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 17 8c 63 00 00 01 28 76 00 00 0a 16 8c 63 00 00 01 15 8c 63 00 00 01 12 02 12 03 28 ?? 00 00 0a 13 04 11 04 39 a6 01 00 00 06 18 6f ?? 00 00 0a 74 0c 00 00 1b 06 16 6f ?? 00 00 0a 74 0a 00 00 1b 09 28 79 00 00 0a 91 6f ?? 00 00 0a 00 07 17 5d 16 fe 01 13 05 11 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}