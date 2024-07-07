
rule Trojan_BAT_RedLineStealer_SDVF_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SDVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 16 18 01 00 0c 2b 13 00 07 08 20 00 01 00 00 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 90 00 } //1
		$a_01_1 = {47 00 6f 00 74 00 68 00 69 00 63 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 73 00 } //1 GothicCheckers
		$a_01_2 = {42 00 61 00 64 00 41 00 70 00 70 00 6c 00 65 00 } //1 BadApple
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}