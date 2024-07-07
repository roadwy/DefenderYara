
rule Trojan_BAT_Razy_PSHE_MTB{
	meta:
		description = "Trojan:BAT/Razy.PSHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 28 29 00 00 0a 0a 02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 28 84 00 00 0a 02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 18 18 73 30 00 00 0a 0b 06 73 7e 00 00 0a 0c 08 6f 7f 00 00 0a 08 6f 80 00 00 0a 13 0b 2b 14 12 0b 28 81 00 00 0a 0d 07 09 66 1f 53 61 d2 6f 36 00 00 0a 12 0b 28 82 00 00 0a 2d e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}