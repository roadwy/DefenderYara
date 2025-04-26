
rule Trojan_BAT_Rozena_NT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 12 00 00 0a 13 04 06 28 13 00 00 0a 73 14 00 00 0a 13 09 11 09 11 04 16 73 15 00 00 0a 13 0a 73 16 00 00 0a 13 0b 11 0a 11 0b 6f 17 00 00 0a 11 0b 6f 18 00 00 0a 13 05 de 24 } //3
		$a_01_1 = {11 06 11 05 8e 69 1f 20 12 07 28 02 00 00 06 26 16 13 08 16 16 11 06 7e 1a 00 00 0a 16 12 08 28 03 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}