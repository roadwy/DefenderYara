
rule Trojan_Win32_Miuref_G_{
	meta:
		description = "Trojan:Win32/Miuref.G!!Miuref,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 3d c7 50 58 e8 75 90 01 01 c7 05 90 01 04 01 00 00 00 90 00 } //2
		$a_03_1 = {50 6a 40 68 00 04 00 00 ff 75 f4 ff 15 90 01 04 85 c0 74 37 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8 90 01 04 83 c4 10 68 60 ea 00 00 ff 15 90 01 04 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8 90 00 } //1
		$a_01_2 = {8b 45 f8 8b 00 83 78 28 00 74 2e 8b 45 f8 8b 00 8b 4d f8 8b 49 04 03 48 28 89 4d fc 74 1b 6a ff 6a 01 ff 75 0c ff 55 fc } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}