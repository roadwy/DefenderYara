
rule Backdoor_Win32_Unskal_C{
	meta:
		description = "Backdoor:Win32/Unskal.C,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f9 2b fa 8a 0a 84 c9 74 90 01 01 80 f1 2a 46 90 02 02 88 0c 17 90 02 08 42 90 02 07 3b 90 01 01 72 90 00 } //05 00 
		$a_01_1 = {53 8d 59 ff 03 de 8a 0b 8b c2 80 e9 30 25 01 00 00 80 79 05 48 83 c8 fe 40 74 0a 02 c9 80 f9 09 7e 03 80 c1 f7 0f be c9 03 f9 42 4b 3b d6 72 d6 8b 4d fc 5b 8b c7 6a 0a 99 5f f7 ff 85 d2 74 04 } //05 00 
		$a_01_2 = {83 f9 5e 75 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb cc 8b 45 fc 83 c0 01 89 45 fc c7 45 e4 00 00 00 00 eb 09 8b 4d e4 83 c1 01 89 4d e4 83 7d e4 33 73 2b 8b 55 fc 0f b6 02 50 e8 bb fe ff ff 83 c4 04 85 c0 74 0b 8b 4d f4 83 c1 01 89 4d f4 eb 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb c6 83 7d f4 07 72 06 83 7d f4 32 } //05 00 
		$a_01_3 = {6f 70 72 61 74 3d 32 26 75 69 64 3d 25 49 36 34 75 26 75 69 6e 66 6f 3d 25 73 26 77 69 6e 3d 25 64 2e 25 64 26 76 65 72 73 3d 25 73 } //05 00  oprat=2&uid=%I64u&uinfo=%s&win=%d.%d&vers=%s
		$a_03_4 = {5c 46 69 6e 64 53 74 72 90 02 01 5c 52 65 6c 65 61 73 65 5c 46 69 6e 64 53 74 72 2e 70 64 62 00 90 00 } //01 00 
		$a_01_5 = {2f 76 69 65 77 74 6f 70 69 63 2e 70 68 70 00 } //01 00 
		$a_01_6 = {5b 50 72 69 6e 74 53 63 72 65 65 6e 5d } //00 00  [PrintScreen]
		$a_00_7 = {5d 04 00 00 05 32 03 } //80 5c 
	condition:
		any of ($a_*)
 
}