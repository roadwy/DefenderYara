
rule PWS_Win32_Sagic_gen_kit{
	meta:
		description = "PWS:Win32/Sagic.gen!kit,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 20 74 61 73 6b 6d 67 72 } //01 00  Disable taskmgr
		$a_01_1 = {44 69 73 61 62 6c 65 20 52 65 67 45 64 69 74 } //01 00  Disable RegEdit
		$a_01_2 = {41 6c 74 20 2b 20 30 } //02 00  Alt + 0
		$a_01_3 = {70 6f 77 65 72 46 75 6c 6c 20 70 61 73 73 77 6f 72 64 } //01 00  powerFull password
		$a_01_4 = {45 78 70 49 6f 72 65 72 2e 65 78 65 } //01 00  ExpIorer.exe
		$a_01_5 = {74 61 73 6b 6d 67 72 5f 33 32 2e 65 78 65 } //01 00  taskmgr_32.exe
		$a_01_6 = {73 79 73 74 65 6d 5f 33 32 2e 65 78 65 } //01 00  system_32.exe
		$a_01_7 = {69 6e 74 72 61 6e 65 74 2e 65 78 65 } //01 00  intranet.exe
		$a_01_8 = {59 61 68 6f 6f 21 20 49 44 } //01 00  Yahoo! ID
		$a_01_9 = {4d 79 50 69 63 2e 6a 70 67 2e 73 63 72 } //01 00  MyPic.jpg.scr
		$a_01_10 = {4d 79 50 69 63 2e 6a 70 67 2e 65 78 65 } //01 00  MyPic.jpg.exe
		$a_01_11 = {4d 79 50 69 63 2e 6a 70 67 2e 70 69 66 } //01 00  MyPic.jpg.pif
		$a_01_12 = {46 69 72 65 77 61 6c 6c } //00 00  Firewall
	condition:
		any of ($a_*)
 
}