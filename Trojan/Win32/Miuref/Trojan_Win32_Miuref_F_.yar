
rule Trojan_Win32_Miuref_F_{
	meta:
		description = "Trojan:Win32/Miuref.F!!Miuref,SIGNATURE_TYPE_ARHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 06 8b 48 28 85 c9 74 1a 8b 46 04 03 c1 74 13 6a ff 6a 01 6a 00 ff d0 } //16
		$a_01_1 = {bb 6b 09 14 00 74 34 8a 0c 3a 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b db 1f 03 d9 47 3b fe 72 de 81 fb c7 50 58 e8 } //2
		$a_03_2 = {b8 6b 09 14 00 74 90 01 01 8a 0c 16 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b c0 1f 03 c1 42 3b d7 72 de 90 00 } //1
		$a_03_3 = {3d c7 50 58 e8 75 90 01 01 c7 05 90 01 04 01 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*16+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=18
 
}