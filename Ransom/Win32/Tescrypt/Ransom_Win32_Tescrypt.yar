
rule Ransom_Win32_Tescrypt{
	meta:
		description = "Ransom:Win32/Tescrypt,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 ffffff9c ffffffff "
		
	strings :
		$a_01_0 = {54 65 73 6c 61 43 72 79 70 74 44 65 63 6f 64 65 72 2e 64 6c 6c 00 47 65 74 53 70 65 63 69 61 6c 53 74 61 74 69 73 74 69 63 73 43 6f 75 6e 74 00 } //9c ff 
		$a_01_1 = {70 74 00 50 65 74 79 61 44 65 63 72 79 70 74 4b 65 79 00 53 63 61 6e 41 6e 64 44 65 63 72 79 70 74 00 53 65 74 44 65 63 72 79 70 74 50 61 74 68 } //9c ff  瑰倀瑥慹敄牣灹䭴祥匀慣䅮摮敄牣灹t敓䑴捥祲瑰慐桴
		$a_00_2 = {2f 69 6e 66 2e 73 61 66 65 2e 33 36 30 2e 63 6e 2f 61 70 69 2f 6b 65 79 3f 6b 65 79 3d } //02 00  /inf.safe.360.cn/api/key?key=
		$a_80_3 = {52 4f 4f 54 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //ROOT\SecurityCenter2  02 00 
		$a_80_4 = {4e 6f 2d 41 6e 74 69 76 69 72 75 73 } //No-Antivirus  02 00 
		$a_80_5 = {2e 69 62 61 6e 6b } //.ibank  02 00 
		$a_80_6 = {2e 77 61 6c 6c 65 74 } //.wallet  04 00 
		$a_80_7 = {55 6e 6c 6f 63 6b 5f 66 69 6c 65 73 5f } //Unlock_files_  04 00 
		$a_80_8 = {41 6c 6d 61 20 4c 6f 63 6b 65 72 } //Alma Locker  04 00 
		$a_80_9 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //Your files are encrypted!  04 00 
		$a_01_10 = {83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05 83 c8 ff 8b d0 } //00 00 
		$a_00_11 = {7e 15 00 00 00 0b 1e f8 b0 31 f3 6e } //3a 89 
	condition:
		any of ($a_*)
 
}