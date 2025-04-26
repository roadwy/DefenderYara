
rule Trojan_BAT_DarkTortilla_UEAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.UEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 11 09 74 ?? 00 00 01 6f ?? 00 00 0a 11 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 0a } //2
		$a_03_1 = {02 07 75 25 00 00 1b 6f ?? 00 00 0a 11 0a 74 ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 16 13 19 2b b5 } //3
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}