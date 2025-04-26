
rule Trojan_BAT_CobaltStrike_MAAL_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 13 0e 11 0e 07 8e 69 32 de } //1
		$a_01_1 = {16 13 0e 2b 1b 07 11 0e 8f 35 00 00 01 25 47 06 11 0e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}