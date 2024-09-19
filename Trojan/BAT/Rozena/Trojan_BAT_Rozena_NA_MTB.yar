
rule Trojan_BAT_Rozena_NA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 00 70 6f ?? 00 00 0a 0c 07 8e 69 8d ?? 00 00 01 0d 16 13 06 2b 18 09 11 06 07 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1 } //3
		$a_03_1 = {01 13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 26 09 11 07 28 ?? 00 00 0a de 1b } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}