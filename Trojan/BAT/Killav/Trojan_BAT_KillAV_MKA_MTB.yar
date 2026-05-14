
rule Trojan_BAT_KillAV_MKA_MTB{
	meta:
		description = "Trojan:BAT/KillAV.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 1c 00 00 0a 72 4b 01 00 70 6f 1d 00 00 0a 0a 28 1c 00 00 0a 72 5d 01 00 70 6f 1d 00 00 0a 0b 28 1c 00 00 0a 06 6f 1e 00 00 0a 28 02 00 00 06 0c 08 7e 10 00 00 0a 28 11 00 00 0a 2c 05 16 13 06 de 77 } //20
		$a_01_1 = {18 72 1f 00 00 70 a2 11 08 19 72 31 00 00 70 a2 11 08 1a 72 43 00 00 70 a2 11 08 1b 72 53 00 00 70 a2 11 08 1c 72 6b 00 00 70 a2 11 08 1d 72 81 00 00 70 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}