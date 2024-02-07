
rule TrojanClicker_Win32_Webin_A{
	meta:
		description = "TrojanClicker:Win32/Webin.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d } //02 00  {871C5380-42A0-1069-A2EA-08002B30309D}
		$a_01_1 = {72 61 76 6d 6f 6e 64 2e 65 78 65 } //02 00  ravmond.exe
		$a_01_2 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_01_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 } //01 00  \Internet Explorer\New Windows
		$a_01_4 = {50 6f 70 75 70 4d 67 72 20 54 72 75 65 } //01 00  PopupMgr True
		$a_01_5 = {5c 57 65 62 4e 65 77 2e 69 6e 69 } //01 00  \WebNew.ini
		$a_01_6 = {5c 57 65 62 2e 69 6e 69 } //01 00  \Web.ini
		$a_01_7 = {00 63 79 69 6b 79 2e 64 6c 6c 00 } //01 00 
		$a_01_8 = {26 68 61 72 64 69 64 3d } //01 00  &hardid=
		$a_01_9 = {26 6e 65 74 69 64 3d } //00 00  &netid=
	condition:
		any of ($a_*)
 
}