
rule Trojan_Win32_Aptdrop_A{
	meta:
		description = "Trojan:Win32/Aptdrop.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 5c 55 73 65 72 73 5c 4e 61 75 67 68 74 79 20 44 65 76 65 6c 6f 70 5c 44 65 73 6b 74 6f 70 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 35 2d 77 69 74 68 2d 63 6d 64 2d 72 65 73 6f 75 72 63 65 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 33 5c 52 65 6c 65 61 73 65 5c 42 61 63 6b 64 6f 6f 72 2e 70 64 62 } //01 00  :\Users\Naughty Develop\Desktop\New Backdoor2.5-with-cmd-resource\New Backdoor2.3\Release\Backdoor.pdb
		$a_01_1 = {3a 5c 46 69 72 73 74 42 61 63 6b 44 6f 6f 72 28 32 30 31 35 5f 31 5f 31 30 29 5c 46 69 72 73 74 42 61 63 6b 44 6f 6f 72 28 32 30 31 35 5f 31 5f 31 30 29 5c 52 65 6c 65 61 73 65 5c 46 69 72 73 74 55 72 6c 4d 6f 6e 2e 70 64 62 } //01 00  :\FirstBackDoor(2015_1_10)\FirstBackDoor(2015_1_10)\Release\FirstUrlMon.pdb
		$a_01_2 = {3a 5c 50 48 32 30 31 35 5f 32 2e 32 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 32 5c 4e 65 77 20 42 61 63 6b 64 6f 6f 72 32 2e 32 5c 52 65 6c 65 61 73 65 5c 43 70 70 55 41 43 53 65 6c 66 45 6c 65 76 61 74 69 6f 6e 2e 70 64 62 } //01 00  :\PH2015_2.2\New Backdoor2.2\New Backdoor2.2\Release\CppUACSelfElevation.pdb
		$a_01_3 = {3a 5c 77 6f 72 6b 5c 34 74 68 5c 70 6c 75 67 69 6e 5c 4f 66 66 53 4d 5c 52 65 6c 65 61 73 65 5c 4f 66 66 53 4d 2e 70 64 62 } //01 00  :\work\4th\plugin\OffSM\Release\OffSM.pdb
		$a_01_4 = {3a 5c 77 6f 72 6b 5c 34 74 68 5c 70 6c 75 67 69 6e 5c 53 4d 5c 52 65 6c 65 61 73 65 5c 53 4d 2e 70 64 62 } //01 00  :\work\4th\plugin\SM\Release\SM.pdb
		$a_01_5 = {3a 5c 77 6f 72 6b 5c 6e 31 73 74 5c 41 67 65 6e 74 5c 52 65 6c 65 61 73 65 5c 48 6e 63 55 70 2e 70 64 62 } //01 00  :\work\n1st\Agent\Release\HncUp.pdb
		$a_01_6 = {3a 5c 77 6f 72 6b 5c 6e 31 73 74 5c 41 67 65 6e 74 5c 52 65 6c 65 61 73 65 5c 50 6f 74 50 6c 61 79 65 72 55 70 64 61 74 65 2e 70 64 62 } //00 00  :\work\n1st\Agent\Release\PotPlayerUpdate.pdb
	condition:
		any of ($a_*)
 
}