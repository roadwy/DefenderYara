
rule Worm_Win32_Vercuser_B{
	meta:
		description = "Worm:Win32/Vercuser.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 5f 64 65 6c 28 2c 20 54 73 44 72 76 20 22 5c 53 79 73 74 65 6d 5c 41 75 74 6f 44 72 69 76 65 2e 65 78 65 22 29 } //01 00  kill_del(, TsDrv "\System\AutoDrive.exe")
		$a_01_1 = {6b 69 6c 6c 5f 64 65 6c 28 2c 20 73 74 61 72 74 75 70 20 22 5c 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 2e 6c 6e 6b 22 29 } //01 00  kill_del(, startup "\Internet Security.lnk")
		$a_01_2 = {54 61 73 6b 20 4d 61 6e 61 67 65 72 20 61 68 6b 5f 63 6c 61 73 73 20 41 6e 56 69 72 4d 61 69 6e 46 72 61 6d 65 } //01 00  Task Manager ahk_class AnVirMainFrame
		$a_01_3 = {6b 69 6c 6c 5f 64 65 6c 28 2c 20 6d 79 70 72 67 5f 64 69 72 20 22 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //01 00  kill_del(, myprg_dir "\Windows Defender
		$a_01_4 = {6b 69 6c 6c 5f 64 65 6c 28 2c 20 61 5f 6c 6f 6f 70 66 69 65 6c 64 20 22 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 22 29 } //01 00  kill_del(, a_loopfield ":\autorun.inf")
		$a_01_5 = {5c 30 30 30 62 30 39 32 37 34 62 2e 65 78 65 2c 5c 30 63 66 34 38 2e 65 78 65 2c 5c 36 31 61 36 30 5c 77 65 38 33 62 2e 65 78 65 2c 5c 61 2d 66 61 73 74 2e 65 78 65 2c 5c 61 6d 76 6f 2e 65 78 65 2c 5c 61 62 5c 61 62 65 73 74 2e 65 78 65 2c } //00 00  \000b09274b.exe,\0cf48.exe,\61a60\we83b.exe,\a-fast.exe,\amvo.exe,\ab\abest.exe,
	condition:
		any of ($a_*)
 
}