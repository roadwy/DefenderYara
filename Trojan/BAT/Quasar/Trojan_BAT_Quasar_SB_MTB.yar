
rule Trojan_BAT_Quasar_SB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 07 08 11 07 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 06 7b 90 01 04 11 07 91 61 d2 9c 00 11 07 17 58 13 07 11 07 06 7b 90 01 04 8e 69 fe 04 13 08 11 08 2d c3 90 00 } //01 00 
		$a_01_1 = {67 48 35 6d 6c 4f 46 42 77 31 7a 34 54 6e 59 58 50 55 62 73 75 79 32 79 75 4e 4f 55 76 61 39 54 6a 6e 4a 4a 51 36 66 41 32 58 30 } //01 00  gH5mlOFBw1z4TnYXPUbsuy2yuNOUva9TjnJJQ6fA2X0
		$a_80_2 = {4c 32 38 4d 4d 38 48 4b 42 4d 51 37 39 39 58 } //L28MM8HKBMQ799X  01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}