
rule Trojan_BAT_DarkTortilla_AHCA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AHCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 0a de 51 00 de 49 00 09 14 fe 03 13 08 11 08 2c 07 } //3
		$a_01_1 = {52 00 4c 00 52 00 6f 00 52 00 61 00 52 00 64 00 52 00 } //1 RLRoRaRdR
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}