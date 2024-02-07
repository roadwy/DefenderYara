
rule Worm_Win32_Sheka_A{
	meta:
		description = "Worm:Win32/Sheka.A,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 12 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //0a 00  netsh firewall add allowedprogram
		$a_01_1 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //0a 00  ShowSuperHidden
		$a_01_2 = {48 69 64 64 65 6e } //0a 00  Hidden
		$a_01_3 = {43 4d 44 2e 45 58 45 } //0a 00  CMD.EXE
		$a_01_4 = {5b 61 75 74 6f 72 75 6e 5d } //0a 00  [autorun]
		$a_01_5 = {55 73 65 41 75 74 6f 50 6c 61 79 3d 30 } //0a 00  UseAutoPlay=0
		$a_01_6 = {73 68 65 6c 6c 45 78 65 63 75 74 65 3d 52 65 63 79 63 6c 65 64 5c } //0a 00  shellExecute=Recycled\
		$a_01_7 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 30 } //0a 00  shutdown -s -t 0
		$a_01_8 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 } //0a 00  shutdown -r -t 0
		$a_01_9 = {53 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 70 6f 77 72 70 72 6f 66 2e 64 6c 6c 2c 53 65 74 53 75 73 70 65 6e 64 53 74 61 74 65 } //0a 00  System32\rundll32.exe powrprof.dll,SetSuspendState
		$a_01_10 = {53 74 61 72 74 20 50 61 67 65 } //0a 00  Start Page
		$a_01_11 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //01 00  Shell_TrayWnd
		$a_01_12 = {70 63 20 75 73 65 72 20 64 69 73 61 62 6c 65 } //01 00  pc user disable
		$a_01_13 = {70 63 20 75 73 65 72 20 65 6e 61 62 6c 65 } //01 00  pc user enable
		$a_01_14 = {70 63 20 6c 6f 61 64 } //01 00  pc load
		$a_01_15 = {70 63 20 72 75 6e } //01 00  pc run
		$a_01_16 = {70 63 20 67 6f 75 72 6c } //01 00  pc gourl
		$a_01_17 = {70 63 20 68 6f 6d 65 70 61 67 65 } //00 00  pc homepage
	condition:
		any of ($a_*)
 
}