
rule Trojan_BAT_Heracles_LGN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.LGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 07 09 1f 32 59 6f 10 00 00 0a 13 06 06 11 05 11 06 72 87 00 00 70 1f 0c 28 ?? 00 00 06 26 07 08 1f 32 59 6f 10 00 00 0a 13 05 07 09 1f 32 59 6f 10 00 00 0a 13 06 06 11 05 11 06 72 9f 00 00 70 1f 0a 28 ?? 00 00 06 26 00 11 04 17 58 13 04 11 04 20 88 13 00 00 fe 04 13 08 11 08 2d } //2
		$a_01_1 = {59 00 4f 00 55 00 20 00 49 00 44 00 49 00 4f 00 54 00 21 00 21 00 } //2 YOU IDIOT!!
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}