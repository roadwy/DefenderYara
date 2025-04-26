
rule Trojan_BAT_CobaltStrike_ASEQ_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ASEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 7a 02 28 ?? 00 00 0a 0a 73 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c de } //1
		$a_03_1 = {0b 06 07 28 ?? 00 00 06 0c 08 25 13 04 2c 06 11 04 8e 69 2d 05 16 e0 0d 2b 0a 11 04 16 8f ?? 00 00 01 e0 0d 09 28 ?? 00 00 0a 25 08 8e 69 6a 28 ?? 00 00 0a 1f 40 12 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}