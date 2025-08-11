
rule Trojan_BAT_DarkTortilla_AYSA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AYSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 2c 08 02 8e 69 16 fe 01 2b 01 17 2c 04 14 0a 2b 71 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0b 73 ?? 01 00 0a 0d 09 75 ?? 00 00 01 07 74 ?? 00 00 1b 28 ?? 02 00 06 09 75 ?? 00 00 01 6f ?? 01 00 0a 13 04 11 04 75 ?? 00 00 01 02 28 ?? 02 00 06 0a de 2a } //5
		$a_03_1 = {02 03 16 03 8e 69 6f ?? 01 00 0a 0b 07 75 ?? 00 00 1b 28 ?? 02 00 06 0a 06 75 ?? 00 00 1b 2a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}