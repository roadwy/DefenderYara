
rule Backdoor_Win32_Tapazom_B{
	meta:
		description = "Backdoor:Win32/Tapazom.B,SIGNATURE_TYPE_PEHSTR_EXT,36 01 18 01 07 00 00 ffffffc8 00 "
		
	strings :
		$a_03_0 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 90 01 02 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03 90 00 } //32 00 
		$a_01_1 = {6d 6d 7a 6f 2e 64 79 6e 64 6e 73 2e 6f 72 67 3a 31 34 33 31 } //32 00  mmzo.dyndns.org:1431
		$a_01_2 = {43 61 72 76 69 65 72 } //1e 00  Carvier
		$a_01_3 = {07 49 6e 66 2e 65 78 65 08 55 74 69 6c 69 74 79 } //1e 00  䤇普攮數唈楴楬祴
		$a_01_4 = {16 48 49 44 2d 49 6e 74 65 72 66 61 63 65 73 20 44 65 76 69 63 65 ae 00 } //0a 00 
		$a_01_5 = {75 74 69 6c 69 2e 65 78 65 } //0a 00  utili.exe
		$a_01_6 = {77 69 64 2e 64 6c 6c } //00 00  wid.dll
		$a_00_7 = {80 10 00 00 e5 5b 44 51 9a 26 7f 35 ab 6e 43 7a 00 10 00 80 5d 04 00 00 1a ce 02 80 5c 20 00 00 57 ce 02 80 00 00 01 00 25 00 0a 00 8f 01 43 61 6e 72 61 6e 2e 41 00 00 01 40 05 82 5d 00 04 00 80 10 00 00 ef be bc 58 72 5e 8a 7e 36 fa d9 ab 82 02 00 80 5d 04 00 00 57 ce } //02 80 
	condition:
		any of ($a_*)
 
}