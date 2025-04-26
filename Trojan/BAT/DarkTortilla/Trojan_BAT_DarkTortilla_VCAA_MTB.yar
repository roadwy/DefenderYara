
rule Trojan_BAT_DarkTortilla_VCAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.VCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 08 74 ?? 00 00 01 6f ?? 00 00 0a 16 13 13 2b bf 11 07 75 ?? 00 00 01 6f ?? 00 00 0a 0d de 49 } //3
		$a_03_1 = {11 07 75 84 00 00 01 11 06 75 ?? 00 00 01 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 08 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}