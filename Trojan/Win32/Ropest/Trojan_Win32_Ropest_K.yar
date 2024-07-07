
rule Trojan_Win32_Ropest_K{
	meta:
		description = "Trojan:Win32/Ropest.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 41 53 54 45 52 4f 50 45 } //1
		$a_01_1 = {2f 65 6e 63 2f 64 00 } //1
		$a_00_2 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //1
		$a_03_3 = {8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c1 25 ff 00 00 00 8a 84 90 01 03 ff ff 32 04 37 88 06 46 90 00 } //1
		$a_01_4 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01 } //1
		$a_01_5 = {81 38 21 43 46 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}