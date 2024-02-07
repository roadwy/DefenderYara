
rule Backdoor_Win32_PcClient_DK{
	meta:
		description = "Backdoor:Win32/PcClient.DK,SIGNATURE_TYPE_PEHSTR_EXT,51 00 50 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //0a 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 } //0a 00  SYSTEM\CurrentControlSet\Services
		$a_00_2 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 } //0a 00  CurrentControlSet
		$a_00_3 = {50 63 4d 61 69 6e 2e 64 6c 6c } //0a 00  PcMain.dll
		$a_00_4 = {44 6f 53 65 72 76 69 63 65 } //0a 00  DoService
		$a_00_5 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 } //0a 00  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)
		$a_00_6 = {69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00 } //0a 00  image/jpeg
		$a_03_7 = {74 16 68 b8 0b 00 00 ff 15 90 01 03 10 68 90 01 03 10 ff 15 90 01 03 10 ff 15 90 01 03 10 a3 14 90 01 02 10 90 00 } //01 00 
		$a_00_8 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //00 00  \svchost.exe -k 
	condition:
		any of ($a_*)
 
}