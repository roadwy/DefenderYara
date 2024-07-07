
rule Trojan_Win32_Alureon_FQ{
	meta:
		description = "Trojan:Win32/Alureon.FQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 45 90 01 01 8b 4d 90 01 01 8a 00 85 c9 75 06 04 44 34 cc eb 90 00 } //1
		$a_03_1 = {33 c0 89 04 24 68 90 01 04 58 93 01 1c 24 33 c9 0b 0c 24 90 00 } //1
		$a_01_2 = {c7 45 e0 63 5c 5d 5e c7 45 e4 5f 78 79 7a c7 45 e8 7b 74 75 76 } //1
		$a_03_3 = {0f b6 4c 05 bc 81 e9 90 01 01 00 00 00 81 f1 90 01 01 00 00 00 88 4d ff 8a 4d ff 0f b6 c9 88 84 0d 38 ff ff ff 40 83 f8 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}