
rule Trojan_BAT_LummaC_AMKA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 20 } //3
		$a_01_1 = {02 11 31 11 36 9c 20 } //2
		$a_03_2 = {11 2d 17 58 7e ?? 00 00 04 28 ?? 01 00 06 11 2f 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 5d 13 2d 38 ?? ?? 00 00 11 35 11 31 6f ?? 00 00 0a 20 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=7
 
}