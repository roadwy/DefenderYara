
rule Trojan_BAT_Heracles_PRE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 a1 00 00 0a 20 e6 3a 5d b5 28 4d 00 00 0a 6f ?? 00 00 0a 6f ?? 02 00 0a 11 04 1f 10 8d 07 00 00 01 6f ?? 02 00 0a 11 04 17 6f ?? 02 00 0a 73 5d 02 00 0a 13 05 11 05 11 04 6f ?? 02 00 0a 17 73 89 02 00 0a 13 06 11 06 09 16 09 8e 69 6f c6 00 00 0a 11 06 6f 8a 02 00 0a 11 05 6f 2f 01 00 0a 0d 11 05 6f 8b 02 00 0a 11 06 6f 8b 02 00 0a 73 5d 02 00 0a 13 07 09 73 02 01 00 0a 16 73 8c 02 00 0a 13 0b 20 00 04 00 00 13 0c 11 0c 8d 07 00 00 01 13 0e 11 0b 11 0e 16 11 0c 6f ?? 01 00 0a 13 0d 2b 1a 11 07 11 0e 16 11 0d 6f ?? 00 00 0a 11 0b 11 0e 16 11 0c 6f ?? 01 00 0a 13 0d 11 0d 16 30 e1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}