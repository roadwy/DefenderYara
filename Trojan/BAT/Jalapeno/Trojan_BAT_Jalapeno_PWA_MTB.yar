
rule Trojan_BAT_Jalapeno_PWA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 22 c3 f5 48 40 6f ?? 00 00 0a 26 2b 64 00 73 ac 00 00 0a 13 05 11 05 07 6f ?? 00 00 0a 26 11 05 07 6f ?? 00 00 0a 26 73 af 00 00 0a 13 06 11 06 72 c3 08 00 70 6f ?? 00 00 0a 00 11 06 6f ?? 00 00 0a 26 02 09 03 04 28 ?? 00 00 06 00 73 b2 00 00 0a 25 23 b6 f3 fd d4 41 4c 12 41 6f ?? 00 00 0a 00 13 07 11 07 6f ?? 00 00 0a 00 09 17 58 0d 00 09 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 08 11 08 2d 81 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}