
rule Trojan_Win32_Pucodex_A{
	meta:
		description = "Trojan:Win32/Pucodex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 } //01 00 
		$a_03_1 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8 8b 90 01 01 fc 0f be 02 33 45 f8 90 00 } //01 00 
		$a_03_2 = {3d e5 03 00 00 90 02 08 68 e8 03 00 00 ff 15 90 01 04 eb 90 00 } //01 00 
		$a_01_3 = {0f be 44 05 d4 83 e8 30 0f af 45 fc 99 6a 1a 59 f7 f9 83 c2 61 } //01 00 
		$a_01_4 = {c6 45 f4 76 c6 45 f5 73 c6 45 f6 6d c6 45 f7 6f c6 45 f8 6e c6 45 f9 2e c6 45 fa 65 c6 45 fb 78 c6 45 fc 65 } //01 00 
		$a_01_5 = {c6 45 f8 61 c6 45 f9 76 c6 45 fa 70 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65 } //01 00 
		$a_01_6 = {25 73 3f 61 63 74 3d 25 73 26 75 69 64 3d 25 73 } //01 00  %s?act=%s&uid=%s
		$a_01_7 = {6e 65 78 74 63 61 6c 6c 00 00 00 00 74 61 73 6b 5f 69 64 00 74 61 73 6b 5f 74 79 70 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}