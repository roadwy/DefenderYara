
rule Trojan_Win32_Qakbot_RQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 8b 54 24 0c 8a c1 66 2b 17 f6 ea 66 89 54 24 0c 8a c8 0f b7 c2 99 80 c1 48 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_RQ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 46 69 6e 69 73 68 65 61 74 5c 61 6c 77 61 79 73 4d 61 79 5c 52 65 70 72 65 73 65 6e 74 65 6c 65 63 74 72 69 63 5c 66 69 6e 61 6c 57 68 65 65 6c 5c 50 72 69 6e 74 53 65 65 6d 5c 73 65 6e 74 2e 70 64 62 } //10 c:\Finisheat\alwaysMay\Representelectric\finalWheel\PrintSeem\sent.pdb
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 20 20 52 65 6d 6f 74 65 53 69 67 6e 65 64 } //1 C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe   RemoteSigned
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //1 GetStartupInfoA
		$a_01_5 = {20 52 65 63 65 69 76 65 2d 4a 6f 62 2e } //1  Receive-Job.
		$a_01_6 = {47 65 74 43 50 49 6e 66 6f } //1 GetCPInfo
		$a_01_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_01_8 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_9 = {31 3a 20 41 6e 6f 6e 79 6d 6f 75 73 20 28 } //1 1: Anonymous (
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=17
 
}