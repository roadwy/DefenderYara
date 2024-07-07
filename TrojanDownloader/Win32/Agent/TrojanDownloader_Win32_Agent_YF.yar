
rule TrojanDownloader_Win32_Agent_YF{
	meta:
		description = "TrojanDownloader:Win32/Agent.YF,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 4d 53 53 65 72 76 69 63 65 2e 65 78 65 } //10 C:\WINDOWS\SYSTEM32\MSService.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 64 66 32 30 2e 64 6f 74 35 68 6f 73 74 69 6e 67 2e 63 6f 6d 2f 7e 73 68 69 74 73 68 69 72 } //10 http://df20.dot5hosting.com/~shitshir
		$a_01_2 = {b8 4f ec c4 4e f7 e9 c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 c1 e0 02 01 d0 01 c0 29 c1 89 c8 0f be 44 28 c8 89 45 a0 eb } //10
		$a_01_3 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //1 SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_4 = {4d 53 55 70 64 61 74 65 53 76 63 } //1 MSUpdateSvc
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=32
 
}