
rule TrojanDownloader_Win32_Harnig_gen_E{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 13 00 1e 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 64 76 36 } //01 00  adv6
		$a_00_1 = {61 64 76 37 } //01 00  adv7
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_01_3 = {64 6c 75 6e 69 71 } //01 00  dluniq
		$a_01_4 = {70 61 79 64 69 61 6c 2e 74 78 74 } //01 00  paydial.txt
		$a_01_5 = {5c 70 61 79 64 69 61 6c 2e 65 78 65 } //01 00  \paydial.exe
		$a_01_6 = {70 61 79 74 69 6d 65 2e 74 78 74 } //01 00  paytime.txt
		$a_00_7 = {5c 70 61 79 74 69 6d 65 2e 65 78 65 } //01 00  \paytime.exe
		$a_01_8 = {5c 63 6f 75 6e 74 72 79 64 69 61 6c 2e 65 78 65 } //01 00  \countrydial.exe
		$a_00_9 = {74 69 62 73 2e 70 68 70 } //01 00  tibs.php
		$a_01_10 = {5c 74 69 62 73 2e 65 78 65 } //01 00  \tibs.exe
		$a_01_11 = {5c 64 69 6d 61 6b } //01 00  \dimak
		$a_01_12 = {5c 75 6e 69 71 5c 6b 6c 2e 65 78 65 5c } //05 00  \uniq\kl.exe\
		$a_02_13 = {61 64 76 3d 61 64 76 90 01 03 26 63 6f 64 65 31 3d 48 4e 4e 45 26 63 6f 64 65 32 3d 35 31 32 31 90 00 } //05 00 
		$a_01_14 = {68 74 74 70 3a 2f 2f 31 39 35 2e 39 35 2e 32 31 38 2e 31 37 33 2f 64 6c 2f 64 6c 2e 70 68 70 3f } //05 00  http://195.95.218.173/dl/dl.php?
		$a_01_15 = {68 74 74 70 3a 2f 2f 31 39 35 2e 39 35 2e 32 31 38 2e 31 37 33 2f 74 72 6f 79 73 2f } //01 00  http://195.95.218.173/troys/
		$a_01_16 = {6e 65 77 64 69 61 6c 31 2e 74 78 74 20 20 } //01 00  newdial1.txt  
		$a_01_17 = {5c 6e 65 77 64 69 61 6c 31 2e 65 78 65 20 20 } //01 00  \newdial1.exe  
		$a_01_18 = {6e 65 77 64 69 61 6c 2e 74 78 74 20 } //02 00  newdial.txt 
		$a_01_19 = {64 6c 2f 64 6c 75 6e 69 71 2e 70 68 70 3f } //01 00  dl/dluniq.php?
		$a_01_20 = {5c 73 65 63 75 72 65 33 32 2e 68 74 6d 6c } //01 00  \secure32.html
		$a_01_21 = {74 6f 6f 6c 62 61 72 2e 74 78 74 } //01 00  toolbar.txt
		$a_00_22 = {5c 74 6f 6f 6c 62 61 72 2e 65 78 65 } //01 00  \toolbar.exe
		$a_01_23 = {64 65 67 62 65 73 2e 74 78 74 } //01 00  degbes.txt
		$a_01_24 = {5c 64 65 67 62 65 73 2e 65 78 65 } //01 00  \degbes.exe
		$a_01_25 = {6b 6c 2e 74 78 74 } //01 00  kl.txt
		$a_01_26 = {5c 6b 6c 2e 65 78 65 } //19 00  \kl.exe
		$a_02_27 = {53 55 ff 15 90 01 03 00 bf 90 01 03 00 83 c9 ff 33 c0 6a 90 01 01 f2 ae f7 d1 2b f9 8b f7 8b d1 8b fd 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d 44 24 90 01 01 83 e1 03 50 f3 a4 be 90 01 03 00 56 68 90 01 03 00 68 01 00 00 80 e8 90 01 03 ff 90 00 } //05 00 
		$a_00_28 = {83 c9 ff 33 c0 6a 05 f2 ae f7 d1 2b f9 8b f7 8b d1 8b fd 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d } //05 00 
		$a_00_29 = {8a 17 8a ca 3a 10 75 1c 84 c9 74 12 8a 57 01 8a ca 3a 50 01 75 0e 47 47 40 40 84 c9 75 e2 33 ff 33 c0 eb 07 1b 0c 83 d8 ff 33 ff 3b c7 } //00 00 
	condition:
		any of ($a_*)
 
}