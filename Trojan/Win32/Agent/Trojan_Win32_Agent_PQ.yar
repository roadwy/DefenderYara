
rule Trojan_Win32_Agent_PQ{
	meta:
		description = "Trojan:Win32/Agent.PQ,SIGNATURE_TYPE_PEHSTR,21 00 1e 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 20 79 69 6e 68 75 2e 64 6c 6c 20 49 6e 73 74 61 6c 6c 20 0d 0a 20 6e 65 74 20 73 74 61 72 74 20 49 50 52 49 50 0d 0a 00 77 62 2b 00 5c 79 69 6e 68 75 2e 62 61 74 00 00 62 61 74 2e 62 61 74 } //10
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 79 69 6e 68 75 2e 62 61 74 } //10 C:\WINDOWS\SYSTEM32\yinhu.bat
		$a_01_2 = {4c 65 6e 67 46 65 6e 67 54 72 6f 6a 61 6e } //10 LengFengTrojan
		$a_01_3 = {52 45 53 45 54 48 4f 53 54 20 69 73 20 6f 6b } //1 RESETHOST is ok
		$a_01_4 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29 } //1 RegSetValueEx(ServiceDll)
		$a_01_5 = {53 76 63 48 6f 73 74 2e 44 4c 4c 2e 6c 6f 67 } //1 SvcHost.DLL.log
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=30
 
}