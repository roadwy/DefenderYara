
rule Trojan_Win32_Zbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e } //0a 00  GetProcessWindowStation
		$a_01_1 = {63 3a 5c 46 69 6e 64 48 65 61 72 64 5c 45 6e 64 4c 6f 6f 6b 5c 43 68 61 72 74 42 65 67 61 6e 5c 57 69 6e 53 65 6e 74 65 6e 63 65 5c 52 61 69 6e 2e 70 64 62 } //01 00  c:\FindHeard\EndLook\ChartBegan\WinSentence\Rain.pdb
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_4 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 41 } //01 00  GetLocaleInfoA
		$a_00_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 65 00 6e 00 6f 00 75 00 67 00 68 00 74 00 68 00 6f 00 73 00 65 00 2e 00 64 00 65 00 } //01 00  http://www.enoughthose.de
		$a_01_6 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 } //01 00  GetEnvironmentStrings
		$a_01_7 = {47 65 74 4c 6f 67 69 63 61 6c 50 72 6f 63 65 73 73 6f 72 49 6e 66 6f 72 6d 61 74 69 6f 6e } //0a 00  GetLogicalProcessorInformation
		$a_01_8 = {63 3a 5c 74 68 65 6e 53 70 6f 74 5c 53 68 6f 72 74 46 65 6c 6c 5c 52 69 67 68 74 42 72 61 6e 63 68 5c 52 65 61 63 68 73 6f 75 6e 64 5c 4f 6e 65 47 72 61 73 73 5c 41 6e 2e 70 64 62 } //01 00  c:\thenSpot\ShortFell\RightBranch\Reachsound\OneGrass\An.pdb
		$a_01_9 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 45 78 } //01 00  GetLocaleInfoEx
		$a_01_10 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetCurrentDirectoryA
		$a_01_11 = {31 23 53 4e 41 4e } //01 00  1#SNAN
		$a_01_12 = {31 23 51 4e 41 4e } //00 00  1#QNAN
	condition:
		any of ($a_*)
 
}