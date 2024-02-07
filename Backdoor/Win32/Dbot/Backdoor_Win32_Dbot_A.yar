
rule Backdoor_Win32_Dbot_A{
	meta:
		description = "Backdoor:Win32/Dbot.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 75 74 6f 2e 74 68 65 73 74 61 74 69 73 74 69 63 2e 6f 72 67 2f 63 6d 64 70 32 2e 70 68 70 3f 6b 65 79 3d } //01 00  auto.thestatistic.org/cmdp2.php?key=
		$a_00_1 = {73 65 78 2e 65 78 65 } //01 00  sex.exe
		$a_01_2 = {65 78 70 49 6f 72 65 72 2e 65 78 65 } //01 00  expIorer.exe
		$a_00_3 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //01 00  HttpOpenRequestA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_5 = {57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 20 53 65 72 76 69 63 65 } //01 00  Windows Firewall Service
		$a_00_6 = {56 72 65 6e 6e 61 65 20 4b 6e 6f 63 6b } //01 00  Vrennae Knock
		$a_00_7 = {44 42 6f 74 20 44 65 62 75 67 20 57 69 6e 64 6f 77 } //01 00  DBot Debug Window
		$a_00_8 = {57 69 6e 74 69 6d 65 2e 65 78 65 } //01 00  Wintime.exe
		$a_00_9 = {57 69 6e 66 69 72 65 2e 65 78 65 } //00 00  Winfire.exe
	condition:
		any of ($a_*)
 
}