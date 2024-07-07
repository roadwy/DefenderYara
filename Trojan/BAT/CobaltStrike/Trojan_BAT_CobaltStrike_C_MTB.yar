
rule Trojan_BAT_CobaltStrike_C_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 07 02 09 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1f 90 01 01 59 94 1a 62 07 02 09 17 58 90 00 } //2
		$a_03_1 = {00 00 0a 0b 07 d4 8d 90 01 01 00 00 01 0c 06 08 16 07 69 6f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}