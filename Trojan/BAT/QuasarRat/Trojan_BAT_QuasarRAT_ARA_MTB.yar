
rule Trojan_BAT_QuasarRAT_ARA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 18 63 02 07 91 1c 62 60 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //2
		$a_01_1 = {00 02 07 91 0c 08 66 d2 0c 08 20 f0 00 00 00 5f 1a 63 08 1f 0f 5f 1a 62 60 d2 0c 06 07 08 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}