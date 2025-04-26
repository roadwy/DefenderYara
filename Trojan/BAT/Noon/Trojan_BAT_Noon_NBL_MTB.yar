
rule Trojan_BAT_Noon_NBL_MTB{
	meta:
		description = "Trojan:BAT/Noon.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 16 8f 05 00 00 01 25 47 7e 03 00 00 04 19 11 16 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 16 58 13 16 11 16 11 0e 8e 69 33 d4 } //1
		$a_01_1 = {11 34 11 0d 1d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 08 32 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Noon_NBL_MTB_2{
	meta:
		description = "Trojan:BAT/Noon.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 7e 27 00 00 04 60 80 27 00 00 04 38 80 00 00 00 11 07 2d 56 11 05 11 06 28 58 00 00 06 2c 28 06 20 02 7e c3 04 07 61 09 58 66 66 65 65 66 65 66 66 65 65 66 08 59 61 0a 1f 10 7e 27 00 00 04 60 80 27 00 00 04 2b 49 } //1
		$a_01_1 = {17 11 0b 5f 2d 20 11 21 20 ff ed 49 bf 06 61 07 61 5a 20 c1 30 ed 66 06 59 07 58 58 13 21 11 21 1f 10 64 d1 13 1b 11 1b d2 13 2d 11 1b 1e 63 d1 13 1b 11 1a 11 0b 91 13 29 11 1a 11 0b 11 29 11 25 61 19 11 1f 58 61 11 2d 61 d2 9c 11 29 13 1f 17 11 0b 58 13 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}