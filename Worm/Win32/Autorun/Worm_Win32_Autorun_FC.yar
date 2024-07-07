
rule Worm_Win32_Autorun_FC{
	meta:
		description = "Worm:Win32/Autorun.FC,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 6f 72 6c 64 6e 65 77 73 2e 61 74 68 2e 63 78 2f 75 70 64 61 74 65 } //1 http://worldnews.ath.cx/update
		$a_01_1 = {31 41 45 46 41 35 35 46 2d 36 30 41 36 2d 34 38 31 37 2d 42 32 44 35 2d 31 32 45 32 45 34 38 36 31 37 46 34 } //1 1AEFA55F-60A6-4817-B2D5-12E2E48617F4
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 shell\open\Command=rundll32.exe
		$a_01_4 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_5 = {77 6f 77 6d 67 72 5f 69 73 5f 6c 6f 61 64 65 64 } //1 wowmgr_is_loaded
		$a_01_6 = {43 6f 6d 6d 61 6e 64 3d 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 2e 5c 5c 25 73 2c 49 6e 73 74 61 6c 6c 4d } //1 Command=rundll32.exe .\\%s,InstallM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}