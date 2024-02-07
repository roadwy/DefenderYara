
rule Backdoor_Win32_Meac_A{
	meta:
		description = "Backdoor:Win32/Meac.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 75 71 31 } //01 00  duq1
		$a_01_1 = {4d 00 79 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 6c 00 6e 00 6b 00 } //01 00  MyShell.lnk
		$a_01_2 = {6d 61 6b 65 20 61 20 62 20 63 } //01 00  make a b c
		$a_01_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 43 00 46 00 47 00 2e 00 6c 00 6e 00 6b 00 } //04 00  \SystemCFG.lnk
		$a_01_4 = {25 73 20 23 32 00 00 00 33 36 30 74 72 61 79 2e 65 78 65 } //04 00 
		$a_01_5 = {4b 56 53 72 76 58 50 2e 65 78 65 00 73 79 73 74 65 6d 5c 66 78 73 73 74 2e 64 6c 6c } //00 00  噋牓塶⹐硥e祳瑳浥晜獸瑳搮汬
		$a_00_6 = {5d 04 00 00 5f 0d 03 80 } //5c 1e 
	condition:
		any of ($a_*)
 
}