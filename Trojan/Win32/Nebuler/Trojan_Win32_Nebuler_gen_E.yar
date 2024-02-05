
rule Trojan_Win32_Nebuler_gen_E{
	meta:
		description = "Trojan:Win32/Nebuler.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 23 8b 85 90 01 02 ff ff 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 90 00 } //01 00 
		$a_01_1 = {6a 20 58 64 8b 40 10 85 c0 0f 88 0c 00 00 00 8b 40 0c 8b 70 1c ad 8b 50 08 eb 0c 8b 40 34 33 c9 b1 b8 } //01 00 
		$a_03_2 = {8a da 8d 0c 3a 80 c3 90 01 01 32 1c 08 42 3b d6 88 19 72 ee 90 00 } //01 00 
		$a_03_3 = {8b 4d f0 8b 45 08 8b 55 0c 03 c1 80 c1 90 01 01 32 0c 02 88 08 90 00 } //01 00 
		$a_03_4 = {76 0e 8a 44 0e 01 34 73 88 04 90 01 01 41 3b ca 72 f2 90 00 } //01 00 
		$a_03_5 = {5f 7e 12 8a c8 80 e9 90 01 01 30 8c 05 90 01 02 ff ff 40 3b 45 fc 7c ee ff 75 fc 90 00 } //01 00 
		$a_01_6 = {5b 6d 6f 64 65 6d 5d 00 5b 62 72 61 6e 64 5d 00 } //01 00 
		$a_01_7 = {62 31 30 30 34 2e 64 6c 6c 00 } //01 00 
		$a_01_8 = {0c 52 5f 49 52 58 52 0c 72 6f 26 2f 28 00 } //00 00 
	condition:
		any of ($a_*)
 
}