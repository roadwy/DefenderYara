
rule Trojan_BAT_DarkTortilla_FMAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.FMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 1b 13 0c 2b b4 11 04 75 ?? 00 00 01 17 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 18 6f ?? 00 00 0a 18 13 0c 2b 95 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 05 } //2
		$a_03_1 = {02 16 02 8e 69 6f ?? 00 00 0a de 49 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}