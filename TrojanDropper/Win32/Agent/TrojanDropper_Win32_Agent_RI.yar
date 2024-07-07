
rule TrojanDropper_Win32_Agent_RI{
	meta:
		description = "TrojanDropper:Win32/Agent.RI,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 69 65 64 77 66 2e 65 78 65 } //1 C:\WINDOWS\iedwf.exe
		$a_01_1 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 64 6e 6c 61 75 6e 63 68 65 72 5f 2e 64 6c 6c } //1 Program Files\Windows NT\dnlauncher_.dll
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 71 71 75 70 64 61 74 65 2e 64 6c 6c } //1 C:\WINDOWS\qqupdate.dll
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 70 69 64 20 25 64 20 2f 66 } //1 taskkill.exe /pid %d /f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}