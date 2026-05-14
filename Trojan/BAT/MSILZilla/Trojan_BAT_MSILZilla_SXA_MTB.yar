
rule Trojan_BAT_MSILZilla_SXA_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 05 00 00 06 0a 06 2d 01 2a 73 4b 00 00 06 0b 07 06 16 6f 4e 00 00 06 2c e5 07 6f 43 00 00 06 1f ?? 33 21 02 7b 09 00 00 04 2c 19 02 7b 09 00 00 04 07 1a 6f 52 00 00 06 6f 47 00 00 06 6f 0b 00 00 0a 2b ba 07 6f 43 00 00 06 1f ?? 2e 0a 07 6f 43 00 00 06 1f ?? 33 a6 07 18 6f 52 00 00 06 2c 9d 02 7b 07 00 00 04 0c 16 0d } //20
		$a_01_1 = {06 12 01 28 0c 00 00 0a 02 7b 44 00 00 04 6f 11 00 00 0a 26 02 7b 40 00 00 04 6f 42 00 00 0a 2d 04 14 0c de 25 02 7b 40 00 00 04 6f 46 00 00 0a 02 7b 40 00 00 04 16 6a 6f 47 00 00 0a 0c de 0a } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}