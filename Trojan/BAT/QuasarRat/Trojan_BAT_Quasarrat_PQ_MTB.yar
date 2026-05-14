
rule Trojan_BAT_Quasarrat_PQ_MTB{
	meta:
		description = "Trojan:BAT/Quasarrat.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 02 11 04 91 09 20 ff 00 00 00 5f 61 d2 9c 09 20 0d 66 19 00 5a 20 5f f3 6e 3c 58 0d 11 04 17 58 13 04 11 04 02 8e 69 32 d4 } //5
		$a_03_1 = {00 00 0a 0a 06 16 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d de 23 } //2
		$a_03_2 = {08 11 05 08 11 05 91 19 63 08 11 05 91 1b 62 60 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 e1 08 28 ?? 00 00 0a 08 13 06 de 06 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=8
 
}