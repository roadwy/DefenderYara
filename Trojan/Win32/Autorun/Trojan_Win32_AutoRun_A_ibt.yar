
rule Trojan_Win32_AutoRun_A_ibt{
	meta:
		description = "Trojan:Win32/AutoRun.A!ibt,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //01 00  open=AutoRun.exe
		$a_01_1 = {73 68 65 6c 6c 5c 31 3d 4f 70 65 6e } //01 00  shell\1=Open
		$a_01_2 = {73 68 65 6c 6c 5c 31 5c 43 6f 6d 6d 61 6e 64 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //01 00  shell\1\Command=AutoRun.exe
		$a_01_3 = {73 68 65 6c 6c 5c 32 5c 43 6f 6d 6d 61 6e 64 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //01 00  shell\2\Command=AutoRun.exe
		$a_01_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //01 00  shellexecute=AutoRun.exe
		$a_01_5 = {55 6e 61 62 6c 65 20 74 6f 20 77 72 69 74 65 20 74 6f 20 43 3a 5c 41 55 54 4f 52 55 4e 2e 49 4e 46 } //01 00  Unable to write to C:\AUTORUN.INF
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\
	condition:
		any of ($a_*)
 
}