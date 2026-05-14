
rule Trojan_BAT_Bladabindi_AYK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 11 07 2c 09 11 05 11 07 17 59 91 2b 04 11 04 1d 91 00 13 09 11 06 11 07 91 13 0a 11 07 20 ff 00 00 00 5d d2 13 0b 11 08 11 07 11 05 11 07 91 11 0a 61 11 09 61 11 0b 61 d2 9c 00 11 07 17 58 13 07 11 07 11 05 8e 69 fe 04 13 0f 11 0f 2d b0 } //7
		$a_01_1 = {24 30 30 37 31 38 35 38 35 2d 37 36 35 65 2d 34 37 62 63 2d 38 30 31 33 2d 33 62 34 33 62 31 39 63 64 66 33 39 } //3 $00718585-765e-47bc-8013-3b43b19cdf39
		$a_01_2 = {41 6c 6c 6f 63 41 6e 64 52 75 6e } //1 AllocAndRun
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=11
 
}