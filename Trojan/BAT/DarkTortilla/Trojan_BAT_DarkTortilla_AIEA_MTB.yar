
rule Trojan_BAT_DarkTortilla_AIEA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AIEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 13 07 16 13 08 ?? 13 11 2b c0 11 07 74 0b 00 00 1b 11 08 9a 13 09 07 75 0c 00 00 1b 11 09 75 4b 00 00 01 1f 10 28 ?? 00 00 0a 6f 6d 00 00 0a } //3
		$a_03_1 = {0a 1d 13 13 2b 91 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 0c 11 0c 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 0a dd } //2
		$a_01_2 = {11 08 11 07 74 0b 00 00 1b 8e 69 fe 04 13 0a } //2
		$a_00_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=8
 
}