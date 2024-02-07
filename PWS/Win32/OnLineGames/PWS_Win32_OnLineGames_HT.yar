
rule PWS_Win32_OnLineGames_HT{
	meta:
		description = "PWS:Win32/OnLineGames.HT,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 74 61 72 74 5c 44 4e 46 63 68 69 6e 61 2e 65 78 65 } //01 00  \start\DNFchina.exe
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 54 65 6e 63 65 6e 74 5c 44 4e 46 5c 4a 69 6e 53 68 61 49 4c 6f 76 65 59 6f 75 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tencent\DNF\JinShaILoveYou
		$a_01_2 = {5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c } //01 00  \start\DNFComponent.DLL
		$a_01_3 = {44 4e 46 2e 65 78 65 } //01 00  DNF.exe
		$a_01_4 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //01 00  QQLogin.exe
		$a_01_5 = {2e 73 6f 75 73 75 6f 31 30 30 2e 63 6f 6d 3a } //00 00  .sousuo100.com:
	condition:
		any of ($a_*)
 
}