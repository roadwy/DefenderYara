
rule Trojan_Win32_Coinminer_PA_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.PA!MTB,SIGNATURE_TYPE_PEHSTR,17 00 17 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 51 4c 41 47 45 4e 54 53 57 57 2e 65 78 65 } //4 SQLAGENTSWW.exe
		$a_01_1 = {58 4d 52 2e 65 78 65 7c 58 4d 52 69 67 2e 65 78 65 } //4 XMR.exe|XMRig.exe
		$a_01_2 = {58 4d 52 69 67 20 43 50 55 20 6d 69 6e 65 7c 58 4d 52 69 67 20 4f 70 65 6e 43 4c 20 6d 69 6e 65 72 } //4 XMRig CPU mine|XMRig OpenCL miner
		$a_01_3 = {4d 69 6e 65 72 2e 65 78 65 } //4 Miner.exe
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 61 73 6b 6d 67 7a 72 2e 65 78 65 } //4 C:\ProgramData\taskmgzr.exe
		$a_01_5 = {58 4d 52 2e 65 78 65 } //2 XMR.exe
		$a_01_6 = {58 4d 52 69 67 2e 65 78 65 } //2 XMRig.exe
		$a_01_7 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 cmd /c taskkill /f /im taskmgr.exe
		$a_01_8 = {6d 63 75 70 64 75 69 2e 65 78 65 } //1 mcupdui.exe
		$a_01_9 = {65 67 75 69 2e 65 78 65 } //1 egui.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=23
 
}