
rule Trojan_BAT_DarkTortilla_AAXK_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 13 0b 2b a8 09 75 ?? 00 00 01 09 74 ?? 00 00 01 6f ?? 00 00 0a 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 1b 13 0b 2b 80 } //2
		$a_03_1 = {11 07 74 78 00 00 01 02 28 ?? 00 00 2b 28 ?? 00 00 2b 16 02 8e 69 6f ?? 00 00 0a 18 13 0f 2b c1 11 07 75 ?? 00 00 01 6f ?? 00 00 0a de 49 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}