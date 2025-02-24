
rule Trojan_BAT_CobaltStrike_NIT_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 02 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 02 16 06 6e 28 ?? 00 00 0a 02 8e 69 28 ?? 00 00 0a 7e 1c 00 00 0a 06 6e 28 ?? 00 00 0a 7e 1c 00 00 0a 28 ?? 00 00 06 26 2a } //2
		$a_03_1 = {18 5b 0b 07 8d 1b 00 00 01 0c 16 0d 2b 1d 02 09 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 32 df } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}