
rule Backdoor_Win32_Racdr_A{
	meta:
		description = "Backdoor:Win32/Racdr.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 78 69 61 6f 79 75 00 } //01 00  砀慩祯u
		$a_01_1 = {57 69 6e 52 41 52 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  WinRAR\shell\open\command
		$a_01_2 = {5c 53 74 61 72 74 75 70 5c 51 51 } //01 00  \Startup\QQ
		$a_01_3 = {53 6f 75 67 6f 75 2e 65 78 65 } //01 00  Sougou.exe
		$a_01_4 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_01_5 = {2f 61 63 74 69 76 65 3a 79 65 73 20 26 26 20 6e 65 74 20 75 73 65 72 20 67 75 65 73 74 20 72 61 74 70 70 } //00 00  /active:yes && net user guest ratpp
	condition:
		any of ($a_*)
 
}