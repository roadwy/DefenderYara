
rule Trojan_BAT_ScreenLock_MB_MTB{
	meta:
		description = "Trojan:BAT/ScreenLock.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 6c 65 61 73 65 20 45 6e 74 65 72 20 55 70 64 61 74 65 64 20 50 72 6f 64 75 63 74 20 4b 65 79 } //01 00  Please Enter Updated Product Key
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {73 68 75 74 64 6f 77 6e 20 2d 61 20 2d 74 20 30 27 68 } //01 00  shutdown -a -t 0'h
		$a_81_3 = {68 74 74 70 3a 2f 2f 74 68 65 6d 65 64 69 61 66 6f 78 2e 63 6f 6d 2f 68 69 70 6f 70 32 2f 6c 6f 63 6b 65 72 2f 61 70 69 2f 73 65 6e 64 6b 65 79 } //01 00  http://themediafox.com/hipop2/locker/api/sendkey
		$a_81_4 = {68 74 74 70 3a 2f 2f 74 68 65 6d 65 64 69 61 66 6f 78 2e 63 6f 6d 2f 68 69 70 6f 70 32 2f 6c 6f 63 6b 65 72 2f 61 70 69 2f 6b 65 79 73 74 72 6f 6b 65 } //01 00  http://themediafox.com/hipop2/locker/api/keystroke
		$a_81_5 = {64 69 73 61 62 6c 65 5f 61 64 } //01 00  disable_ad
		$a_81_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskkill /f /im taskmgr.exe
		$a_81_7 = {52 65 6c 65 61 73 65 5c 57 69 6e 20 41 63 74 2e 70 64 62 } //00 00  Release\Win Act.pdb
		$a_00_8 = {5d 04 00 00 2d 44 } //04 80 
	condition:
		any of ($a_*)
 
}