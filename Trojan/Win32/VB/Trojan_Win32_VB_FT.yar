
rule Trojan_Win32_VB_FT{
	meta:
		description = "Trojan:Win32/VB.FT,SIGNATURE_TYPE_PEHSTR,25 00 25 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //0a 00  MSVBVM60.DLL
		$a_01_1 = {4e 74 53 68 75 74 64 6f 77 6e 53 79 73 74 65 6d } //0a 00  NtShutdownSystem
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_3 = {2e 00 62 00 61 00 74 00 } //01 00  .bat
		$a_01_4 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //01 00  cmd /c
		$a_01_5 = {64 00 65 00 6c 00 20 00 25 00 30 00 } //01 00  del %0
		$a_01_6 = {3a 00 5c 00 6e 00 74 00 6c 00 64 00 72 00 } //01 00  :\ntldr
		$a_01_7 = {55 00 73 00 65 00 72 00 49 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  UserInit.exe
		$a_01_8 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 } //01 00  Windows Update
		$a_01_9 = {64 00 6c 00 6c 00 63 00 61 00 63 00 68 00 65 00 5c 00 90 00 02 00 08 00 2e 00 65 00 78 00 65 00 90 00 00 00 } //01 00 
		$a_01_10 = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 31 00 30 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 } //00 00  ping -n 10 localhost > nul
	condition:
		any of ($a_*)
 
}