
rule Trojan_Win32_GuLoader_SIBM2_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 9d 81 34 17 90 01 04 90 02 30 83 c2 04 90 02 30 81 fa 90 01 04 0f 85 90 01 04 90 02 30 ff e7 90 00 } //1
		$a_00_1 = {56 00 61 00 72 00 69 00 61 00 6e 00 74 00 66 00 75 00 6e 00 6b 00 74 00 69 00 6f 00 6e 00 73 00 } //1 Variantfunktions
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_GuLoader_SIBM2_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 00 61 00 6c 00 63 00 6f 00 6d 00 } //1 Malcom
		$a_00_1 = {37 00 2d 00 45 00 76 00 65 00 6e 00 20 00 55 00 50 00 } //1 7-Even UP
		$a_03_2 = {83 e9 04 eb 90 01 04 90 02 4a 90 18 8b 99 90 01 04 90 02 60 33 5d 90 01 01 90 02 30 89 1c 08 90 02 60 83 e9 04 90 02 4a 0f 8d 90 01 04 90 02 80 90 18 90 18 90 02 c0 5b 90 02 85 6a 00 90 02 5a 6a 00 90 02 8a 50 90 02 70 53 90 02 6a 6a 00 90 02 80 6a 00 90 02 20 ff d6 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}