
rule Trojan_BAT_DarkTortilla_ZUAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 17 8d 03 00 00 01 25 16 03 a2 25 0b 14 14 17 8d 87 00 00 01 25 16 17 9c 25 0c 28 ?? 00 00 0a 08 75 09 00 00 1b 16 91 2d 02 2b 11 07 } //3
		$a_01_1 = {06 13 07 11 07 7e 13 01 00 04 1f 20 7e 13 01 00 04 1f 20 94 7e 13 01 00 04 20 ab 00 00 00 94 61 20 db 00 00 00 5f 9e 2c 08 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}