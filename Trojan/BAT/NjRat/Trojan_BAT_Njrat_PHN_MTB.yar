
rule Trojan_BAT_Njrat_PHN_MTB{
	meta:
		description = "Trojan:BAT/Njrat.PHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 6f ?? 00 00 0a 0d 08 09 28 ?? 00 00 0a 07 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 11 04 17 d6 13 04 00 11 04 11 06 fe 04 13 07 11 07 2d ca 08 28 ?? 00 00 0a 0c 08 0a 2b 00 06 2a } //10
		$a_01_1 = {44 61 72 6b 5f 64 65 63 72 79 70 74 } //1 Dark_decrypt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}