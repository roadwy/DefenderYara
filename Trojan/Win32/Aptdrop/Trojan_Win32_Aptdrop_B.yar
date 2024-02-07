
rule Trojan_Win32_Aptdrop_B{
	meta:
		description = "Trojan:Win32/Aptdrop.B,SIGNATURE_TYPE_PEHSTR,33 00 32 00 14 00 00 32 00 "
		
	strings :
		$a_01_0 = {3a 5c 54 41 53 4b 5c 50 72 6f 67 61 6d 73 42 79 4d 65 28 32 30 31 35 2e 31 } //01 00  :\TASK\ProgamsByMe(2015.1
		$a_01_1 = {5c 32 30 31 30 4d 61 69 6e 5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 52 65 6c 65 61 73 65 5c 4d 61 6e 61 67 65 72 2e 70 64 62 } //01 00  \2010Main\EXE_AND_SERVICE\Release\Manager.pdb
		$a_01_2 = {5c 46 69 72 73 74 42 61 63 6b 44 6f 6f 72 28 32 30 31 35 5f 37 5f 32 34 29 5c 52 65 6c 65 61 73 65 5c 6f 66 66 69 63 65 2e 70 64 62 } //01 00  \FirstBackDoor(2015_7_24)\Release\office.pdb
		$a_01_3 = {5c 46 69 72 73 74 42 61 63 6b 64 6f 6f 72 28 32 30 31 35 5f 37 5f 32 34 29 5c 52 65 6c 65 61 73 65 5c 50 72 69 76 69 6c 65 67 65 45 73 63 61 6c 61 74 69 6f 6e 2e 70 64 62 } //01 00  \FirstBackdoor(2015_7_24)\Release\PrivilegeEscalation.pdb
		$a_01_4 = {5c 48 61 70 70 79 5c 32 30 31 30 50 48 56 32 5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 52 65 6c 65 61 73 65 5c 4b 65 79 4c 6f 67 67 65 72 2e 70 64 62 } //01 00  \Happy\2010PHV2\EXE_AND_SERVICE\Release\KeyLogger.pdb
		$a_01_5 = {5c 48 61 70 70 79 5c 32 30 31 30 50 48 56 32 5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 52 65 6c 65 61 73 65 5c 53 63 72 65 65 6e 43 61 70 2e 70 64 62 } //01 00  \Happy\2010PHV2\EXE_AND_SERVICE\Release\ScreenCap.pdb
		$a_01_6 = {5c 48 6e 63 55 70 64 61 74 65 55 41 43 5c 43 2b 2b 5c 52 65 6c 65 61 73 65 5c 43 70 70 55 41 43 53 65 6c 66 45 6c 65 76 61 74 69 6f 6e 2e 70 64 62 } //01 00  \HncUpdateUAC\C++\Release\CppUACSelfElevation.pdb
		$a_01_7 = {5c 48 6e 63 55 70 64 61 74 65 55 41 43 5c 43 2b 2b 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //01 00  \HncUpdateUAC\C++\Release\Installer.pdb
		$a_01_8 = {5c 48 6e 63 55 70 64 61 74 65 55 41 43 5c 43 2b 2b 5c 52 65 6c 65 61 73 65 5c 4d 61 6e 61 67 65 72 5f 54 68 65 6d 2e 70 64 62 } //01 00  \HncUpdateUAC\C++\Release\Manager_Them.pdb
		$a_01_9 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4b 65 79 4c 6f 67 67 65 72 5f 53 63 72 65 65 6e 43 61 70 5f 4d 61 6e 61 67 65 72 5c 52 65 6c 65 61 73 65 5c 53 6f 75 6e 64 52 65 63 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\KeyLogger_ScreenCap_Manager\Release\SoundRec.pdb
		$a_01_10 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4b 65 79 4c 6f 67 67 65 72 5f 53 63 72 65 65 6e 43 61 70 5f 4d 61 6e 61 67 65 72 5c 52 65 6c 65 61 73 65 5c 4d 61 6e 67 65 72 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\KeyLogger_ScreenCap_Manager\Release\Manger.pdb
		$a_01_11 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4b 65 79 4c 6f 67 67 65 72 5f 53 63 72 65 65 6e 43 61 70 5f 4d 61 6e 61 67 65 72 5c 52 65 6c 65 61 73 65 5c 53 63 72 65 65 6e 43 61 70 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\KeyLogger_ScreenCap_Manager\Release\ScreenCap.pdb
		$a_01_12 = {5c 53 68 65 6c 6c 43 6f 64 65 5c 44 65 62 75 67 5c 48 77 70 43 6f 6e 76 65 72 74 2e 70 64 62 } //01 00  \ShellCode\Debug\HwpConvert.pdb
		$a_01_13 = {5c 53 68 65 6c 6c 43 6f 64 65 5c 52 65 6c 65 61 73 65 5c 55 41 43 54 65 73 74 2e 70 64 62 } //01 00  \ShellCode\Release\UACTest.pdb
		$a_01_14 = {5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 44 65 62 75 67 5c 4d 61 6e 61 67 65 72 2e 70 64 62 } //01 00  \EXE_AND_SERVICE\EXE_AND_SERVICE\Debug\Manager.pdb
		$a_01_15 = {5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 45 58 45 5f 41 4e 44 5f 53 45 52 56 49 43 45 5c 52 65 6c 65 61 73 65 5c 54 72 61 6e 73 50 72 6f 78 79 2e 70 64 62 } //01 00  \EXE_AND_SERVICE\EXE_AND_SERVICE\Release\TransProxy.pdb
		$a_01_16 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 49 6e 73 74 61 6c 6c 65 72 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\Installer\Release\Installer.pdb
		$a_01_17 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 34 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 42 44 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\New Backdoor2.4\Release\InstallBD.pdb
		$a_01_18 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 33 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 42 44 2e 70 64 62 } //01 00  \MyWork\Relative Backdoor\New Backdoor2.3\Release\InstallBD.pdb
		$a_01_19 = {5c 4d 79 57 6f 72 6b 5c 52 65 6c 61 74 69 76 65 20 42 61 63 6b 64 6f 6f 72 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 33 2d 77 69 74 68 2d 63 6d 64 2d 72 65 73 6f 75 72 63 65 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 33 5c 52 65 6c 65 61 73 65 5c 42 61 63 6b 64 6f 6f 72 2e 70 64 62 } //00 00  \MyWork\Relative Backdoor\New Backdoor2.3-with-cmd-resource\New Backdoor2.3\Release\Backdoor.pdb
	condition:
		any of ($a_*)
 
}