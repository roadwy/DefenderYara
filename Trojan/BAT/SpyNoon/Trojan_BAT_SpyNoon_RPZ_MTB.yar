
rule Trojan_BAT_SpyNoon_RPZ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 38 1c da ff ff 07 11 04 91 11 08 61 13 09 07 11 04 11 09 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_SpyNoon_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 35 16 2c 23 26 2b 36 2b 3b 2b 3c 2b 41 ?? ?? ?? ?? ?? 1c 2d 16 26 2b 3d 16 2b 3d 8e 69 1c 2d 0e 26 26 26 2b 36 2b 0e 2b 35 2b da 0b 2b e8 } //1
		$a_01_1 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_01_2 = {35 00 2e 00 37 00 35 00 2e 00 31 00 33 00 34 00 2e 00 31 00 34 00 34 00 } //1 5.75.134.144
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}