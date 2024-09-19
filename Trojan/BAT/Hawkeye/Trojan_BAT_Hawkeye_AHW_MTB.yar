
rule Trojan_BAT_Hawkeye_AHW_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 4b 02 8e b7 17 58 8d ?? 00 00 01 0a 16 13 04 16 02 8e b7 17 59 13 06 13 05 2b 34 06 11 05 02 11 05 91 09 61 08 11 04 91 61 9c 08 28 ?? 00 00 0a 11 04 08 8e b7 17 59 33 05 16 13 04 2b 06 11 04 17 58 13 04 11 05 17 58 13 05 2b 03 0c 2b b2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Hawkeye_AHW_MTB_2{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 36 00 00 04 08 07 6f c3 00 00 0a 28 c5 00 00 0a 13 04 28 71 00 00 0a 11 04 16 11 04 8e 69 6f c3 00 00 0a 28 54 01 00 0a 13 05 7e 38 00 00 04 39 18 00 00 00 7e 37 00 00 04 02 11 05 } //2
		$a_01_1 = {38 00 64 00 36 00 38 00 39 00 66 00 39 00 62 00 2d 00 66 00 34 00 33 00 35 00 2d 00 34 00 33 00 65 00 36 00 2d 00 38 00 66 00 34 00 33 00 2d 00 36 00 65 00 34 00 65 00 62 00 36 00 32 00 35 00 37 00 66 00 38 00 65 00 } //1 8d689f9b-f435-43e6-8f43-6e4eb6257f8e
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Hawkeye_AHW_MTB_3{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e b7 17 59 13 06 13 05 2b 2b 11 04 11 05 02 11 05 91 06 61 08 07 91 61 9c 08 28 ?? 00 00 0a 07 08 8e b7 17 59 33 04 16 0b 2b 04 07 17 58 0b 11 05 17 58 } //1
		$a_03_1 = {0d 0c 2b 46 07 08 91 1f 1f 31 24 07 08 91 1f 7f 2f 1d 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 16 58 28 ?? 00 00 0a 59 d2 9c 07 08 91 1f 20 32 02 2b 0e 07 08 07 08 91 1f 5f 58 28 ?? 00 00 0a 9c 08 17 58 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Hawkeye_AHW_MTB_4{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 06 8e b7 17 da 0d 0c 2b 3f 06 08 91 1f 1f fe 02 06 08 91 1f 7f fe 04 5f 2c 14 06 08 13 04 11 04 06 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c 06 08 91 1f 20 2f 0f 06 08 13 04 11 04 06 11 04 91 1f 5f 58 86 9c 08 17 d6 } //1
		$a_01_1 = {06 17 d6 20 00 01 00 00 5d 0a 08 11 08 06 91 d6 20 00 01 00 00 5d 0c 11 08 06 91 0b 11 08 06 11 08 08 91 9c 11 08 08 07 9c 11 08 06 91 11 08 08 91 d6 20 00 01 00 00 5d 13 05 02 50 11 0a 02 50 11 0a 91 11 08 11 05 91 61 9c 11 0a 17 d6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}