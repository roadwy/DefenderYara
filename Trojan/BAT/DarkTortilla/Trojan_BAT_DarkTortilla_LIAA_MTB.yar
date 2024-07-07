
rule Trojan_BAT_DarkTortilla_LIAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.LIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a a2 14 14 16 17 28 90 01 01 00 00 0a 09 14 72 89 0f 00 70 18 8d 90 01 01 00 00 01 25 16 09 25 13 05 14 72 7b 0f 00 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a a2 25 17 09 25 13 06 14 90 00 } //2
		$a_03_1 = {01 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 0c 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a de 16 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}