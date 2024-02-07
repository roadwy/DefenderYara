
rule Worm_Win32_Skincs_A{
	meta:
		description = "Worm:Win32/Skincs.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  explorer\IEXPLORE.EXE
		$a_01_1 = {43 24 5c 53 65 74 75 70 2e 65 78 65 } //01 00  C$\Setup.exe
		$a_01_2 = {43 24 5c 41 75 74 6f 45 78 65 63 2e 62 61 74 } //01 00  C$\AutoExec.bat
		$a_01_3 = {69 66 20 65 78 69 73 74 20 } //01 00  if exist 
		$a_01_4 = {67 6f 74 6f 20 74 72 79 } //01 00  goto try
		$a_01_5 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //01 00  NoDriveTypeAutoRun
		$a_01_6 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_7 = {50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //01 00  Policies\Explorer
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_9 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00  OpenSCManagerA
		$a_01_10 = {3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //01 00  :\AutoRun.inf
		$a_01_11 = {6c 69 76 65 6b 69 73 73 2e 63 6e 2f 6d 61 } //00 00  livekiss.cn/ma
	condition:
		any of ($a_*)
 
}