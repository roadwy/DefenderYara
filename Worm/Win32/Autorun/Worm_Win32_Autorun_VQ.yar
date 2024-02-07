
rule Worm_Win32_Autorun_VQ{
	meta:
		description = "Worm:Win32/Autorun.VQ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  \\autorun.inf
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_2 = {5b 2e 53 68 65 6c 6c 43 6c 61 73 73 49 6e 66 6f 5d } //01 00  [.ShellClassInfo]
		$a_01_3 = {41 50 50 4c 49 43 41 54 49 4f 4e 20 3a 20 4b 45 59 4c 4f 47 47 45 52 } //01 00  APPLICATION : KEYLOGGER
		$a_01_4 = {73 65 74 4c 6f 67 69 6e 53 61 76 69 6e 67 45 6e 61 62 6c 65 64 28 61 4c 6f 67 69 6e 2e 68 6f 73 74 6e 61 6d 65 2c 20 66 61 6c 73 65 29 3b } //01 00  setLoginSavingEnabled(aLogin.hostname, false);
		$a_01_5 = {73 68 6f 77 4c 6f 67 69 6e 4e 6f 74 69 66 69 63 61 74 69 6f 6e 28 61 4e 6f 74 69 66 79 42 6f 78 2c 20 22 70 61 73 73 77 6f 72 64 2d 73 61 76 65 22 } //00 00  showLoginNotification(aNotifyBox, "password-save"
	condition:
		any of ($a_*)
 
}