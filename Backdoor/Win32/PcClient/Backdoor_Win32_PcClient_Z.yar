
rule Backdoor_Win32_PcClient_Z{
	meta:
		description = "Backdoor:Win32/PcClient.Z,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_01_1 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73 } //01 00  SYSTEM\ControlSet001\Services\%s
		$a_01_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_01_3 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00  \svchost.exe -k
		$a_00_4 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_01_5 = {50 63 4d 61 69 6e 2e 64 6c 6c } //01 00  PcMain.dll
		$a_01_6 = {69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00 } //01 00  image/jpeg
		$a_01_7 = {25 30 38 78 2e 74 6d 70 } //01 00  %08x.tmp
		$a_01_8 = {54 65 73 74 46 75 6e 63 } //01 00  TestFunc
		$a_01_9 = {77 69 6e 73 74 61 30 } //01 00  winsta0
		$a_00_10 = {63 6d 64 2e 65 78 65 } //01 00  cmd.exe
		$a_01_11 = {4c 6f 61 64 50 72 6f 66 69 6c 65 } //01 00  LoadProfile
		$a_01_12 = {47 64 69 70 43 72 65 61 74 65 42 69 74 6d 61 70 46 72 6f 6d 48 42 49 54 4d 41 50 } //01 00  GdipCreateBitmapFromHBITMAP
		$a_01_13 = {47 64 69 70 43 72 65 61 74 65 42 69 74 6d 61 70 46 72 6f 6d 53 63 61 6e 30 } //01 00  GdipCreateBitmapFromScan0
		$a_01_14 = {53 48 45 6d 70 74 79 52 65 63 79 63 6c 65 42 69 6e 41 } //01 00  SHEmptyRecycleBinA
		$a_01_15 = {49 6d 70 65 72 73 6f 6e 61 74 65 53 65 6c 66 } //00 00  ImpersonateSelf
	condition:
		any of ($a_*)
 
}