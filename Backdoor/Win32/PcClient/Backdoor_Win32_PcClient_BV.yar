
rule Backdoor_Win32_PcClient_BV{
	meta:
		description = "Backdoor:Win32/PcClient.BV,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73 } //01 00  SYSTEM\ControlSet001\Services\%s
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  SOFTWARE\Classes\HTTP\shell\open\command
		$a_00_2 = {5c 5c 2e 5c 70 69 70 65 5c } //01 00  \\.\pipe\
		$a_00_3 = {57 69 6e 53 74 61 30 } //01 00  WinSta0
		$a_00_4 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //01 00  \svchost.exe -k
		$a_00_5 = {53 65 72 76 69 63 65 44 6c 6c } //01 00  ServiceDll
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_7 = {5b 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d } //01 00  [%04d-%02d-%02d %02d:%02d:%02d]
		$a_00_8 = {25 64 2e 65 78 65 } //01 00  %d.exe
		$a_00_9 = {25 64 2e 74 6d 70 } //01 00  %d.tmp
		$a_00_10 = {75 70 64 61 74 65 65 76 65 6e 74 3d 25 73 3b } //01 00  updateevent=%s;
		$a_00_11 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 } //01 00  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
		$a_00_12 = {50 63 4d 61 69 6e 2e 64 6c 6c } //01 00  PcMain.dll
		$a_00_13 = {44 6f 4d 61 69 6e 57 6f 72 6b } //01 00  DoMainWork
		$a_00_14 = {44 6f 53 65 72 76 69 63 65 } //01 00  DoService
		$a_00_15 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_02_16 = {68 3f 00 0f 00 6a 00 6a 00 ff 15 90 01 04 89 85 fc fd ff ff 83 bd fc fd ff ff 00 75 08 83 c8 ff e9 90 01 04 c6 85 00 fe ff ff 00 b9 7f 00 00 00 33 c0 8d bd 01 fe ff ff f3 ab 66 ab aa 68 c8 00 00 00 8d 85 00 fe ff ff 50 90 90 00 ff 15 90 01 04 68 90 01 04 8d 8d 00 fe ff ff 51 ff 15 90 01 04 8b 55 08 52 8d 85 00 fe ff ff 50 ff 15 90 01 04 6a 00 6a 00 6a 00 6a 00 6a 00 8d 8d 00 fe ff ff 51 6a 01 6a 02 68 10 01 00 00 68 ff 01 0f 00 8b 55 0c 52 8b 45 08 50 8b 90 01 04 51 ff 15 90 01 04 89 85 f8 fd ff ff 83 bd f8 fd ff ff 00 74 0d 8b 95 f8 fd ff ff 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}