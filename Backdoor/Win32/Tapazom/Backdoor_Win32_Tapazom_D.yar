
rule Backdoor_Win32_Tapazom_D{
	meta:
		description = "Backdoor:Win32/Tapazom.D,SIGNATURE_TYPE_PEHSTR_EXT,40 01 ffffffdc 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 03 00 00 00 8d 75 f4 33 db 8d 45 ec 8b cb c1 e1 03 ba ff 00 00 00 d3 e2 23 16 8b cb c1 e1 03 d3 ea e8 } //64 00 
		$a_01_1 = {83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c 8d 85 d4 f8 ff ff 8a 55 f7 e8 } //32 00 
		$a_01_2 = {6d 7a 6f 2e 68 6f 70 74 6f 2e 6f 72 67 3a 31 34 33 31 } //32 00  mzo.hopto.org:1431
		$a_01_3 = {2d 4d 75 6c 74 69 63 6f 72 65 2e 65 78 65 } //14 00  -Multicore.exe
		$a_01_4 = {43 61 72 76 69 65 72 } //0a 00  Carvier
		$a_01_5 = {64 6f 74 33 64 6c 78 65 2e 64 6c 6c } //00 00  dot3dlxe.dll
		$a_00_6 = {87 10 00 00 b1 9e 97 2a bb 08 52 62 0e 7b 02 0b 11 cf 01 00 5d 04 00 00 1b d4 02 80 5c 21 00 00 1c d4 02 80 00 00 01 00 06 00 0b 00 84 21 54 61 70 61 7a 6f 6d 2e 45 00 00 01 40 05 82 42 00 04 00 40 45 00 00 04 00 01 03 00 02 00 00 00 08 30 00 4c 80 98 f7 81 00 00 00 00 00 00 00 00 24 30 00 08 b1 26 8e 65 00 00 00 00 00 00 00 00 } //68 30 
	condition:
		any of ($a_*)
 
}