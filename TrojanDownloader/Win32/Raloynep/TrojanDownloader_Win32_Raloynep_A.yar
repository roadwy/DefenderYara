
rule TrojanDownloader_Win32_Raloynep_A{
	meta:
		description = "TrojanDownloader:Win32/Raloynep.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 1c 31 2a d8 42 83 fa 10 88 1c 31 7c 02 33 d2 41 3b cf 7c e4 } //02 00 
		$a_01_1 = {58 71 69 75 79 63 76 6b 63 54 6a 64 75 71 76 70 6b 76 5f 58 6b 70 68 75 7e 7a 5d 44 78 74 75 66 73 76 59 66 74 75 6d 75 75 63 46 79 77 5e 56 66 79 76 6c 6f 69 75 } //01 00  XqiuycvkcTjduqvpkv_Xkphu~z]DxtufsvYftumuucFyw^Vfyvloiu
		$a_01_2 = {80 48 45 47 35 35 49 3c 3c 34 3a 38 48 35 30 35 4b 3b 49 2e 43 38 35 4b 34 3a 33 45 37 34 49 42 } //01 00 
		$a_01_3 = {6d 76 77 71 3c 31 33 38 39 39 2f 33 36 38 31 35 39 30 34 36 38 31 82 72 76 79 62 7a 32 71 73 66 } //01 00 
		$a_01_4 = {2a 75 75 66 69 75 7a 78 3a 39 21 26 76 22 32 76 25 31 76 00 } //01 00  甪晵畩硺㤺☡≶瘲ㄥv
		$a_01_5 = {2a 75 75 66 69 75 7a 78 3a 39 21 26 76 22 32 74 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 7c 
	condition:
		any of ($a_*)
 
}