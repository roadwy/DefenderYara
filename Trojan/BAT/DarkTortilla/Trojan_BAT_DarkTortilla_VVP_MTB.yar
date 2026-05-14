
rule Trojan_BAT_DarkTortilla_VVP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.VVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 16 9a 28 ?? 02 00 0a 28 ?? 01 00 06 a2 08 19 08 18 9a 74 39 00 00 1b 28 ?? 03 00 06 a2 72 a0 7e 00 70 08 19 9a } //5
		$a_01_1 = {13 04 2b 33 11 04 1f 09 5d 16 fe 01 13 05 11 05 13 06 11 06 2c 11 07 11 04 02 11 04 91 20 94 00 00 00 61 9c 00 2b 0a 00 07 11 04 02 11 04 91 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}