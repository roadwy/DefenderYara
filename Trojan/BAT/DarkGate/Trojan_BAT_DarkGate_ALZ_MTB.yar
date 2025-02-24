
rule Trojan_BAT_DarkGate_ALZ_MTB{
	meta:
		description = "Trojan:BAT/DarkGate.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 72 00 01 00 70 28 10 00 00 0a 0d 1d 8d 16 00 00 01 25 ?? 72 0c 01 00 70 a2 25 17 06 a2 25 18 72 b5 01 00 70 a2 25 19 08 a2 25 1a 72 ef 01 00 70 a2 25 1b 09 a2 25 1c 72 31 02 00 70 a2 28 11 00 00 0a 13 04 73 12 00 00 0a 25 72 ce 06 00 70 6f 13 00 00 0a 00 25 72 e4 06 00 70 11 04 72 38 07 00 70 28 14 00 00 0a 6f 15 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 ?? 6f 17 00 00 0a 00 25 17 6f 18 00 00 0a 00 25 17 6f 19 00 00 0a 00 13 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}