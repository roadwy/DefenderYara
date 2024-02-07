
rule Trojan_Win32_GratefulPos_A_MTB{
	meta:
		description = "Trojan:Win32/GratefulPos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {34 30 36 30 33 32 30 33 34 34 33 37 30 35 35 37 3d 90 01 04 32 30 31 30 30 30 30 30 36 38 36 30 30 30 30 30 90 00 } //01 00 
		$a_01_1 = {25 73 2e 64 61 74 } //01 00  %s.dat
		$a_01_2 = {5c 74 65 6d 70 5c 50 65 72 66 6c 69 62 5f 50 65 72 66 64 61 74 61 5f 66 34 34 2e 64 61 74 } //01 00  \temp\Perflib_Perfdata_f44.dat
		$a_01_3 = {74 74 32 2e 25 73 2e 25 73 } //01 00  tt2.%s.%s
		$a_01_4 = {74 74 31 2e 25 73 2e 25 73 2e 25 73 2e 25 73 } //01 00  tt1.%s.%s.%s.%s
		$a_01_5 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskmgr.exe
		$a_01_6 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_01_7 = {6d 64 6d 2e 65 78 65 } //01 00  mdm.exe
		$a_01_8 = {73 63 68 65 64 2e 65 78 65 } //01 00  sched.exe
		$a_01_9 = {52 65 67 53 72 76 63 2e 65 78 65 } //01 00  RegSrvc.exe
		$a_01_10 = {66 69 72 65 66 6f 78 2e 65 78 65 } //00 00  firefox.exe
	condition:
		any of ($a_*)
 
}