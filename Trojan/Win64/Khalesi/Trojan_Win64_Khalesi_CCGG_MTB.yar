
rule Trojan_Win64_Khalesi_CCGG_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.CCGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_01_1 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_01_2 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //1 procmon.exe
		$a_01_3 = {69 64 61 71 2e 65 78 65 } //1 idaq.exe
		$a_01_4 = {77 69 6e 64 62 67 2e 65 78 65 } //1 windbg.exe
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 48 54 54 50 44 65 62 75 67 67 65 72 53 76 63 2e 65 78 65 } //1 taskkill /f /im HTTPDebuggerSvc.exe
		$a_01_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 68 74 74 70 64 65 62 75 67 67 65 72 } //1 taskkill /FI "IMAGENAME eq httpdebugger
		$a_01_7 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //1 taskkill /FI "IMAGENAME eq processhacker
		$a_01_8 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 66 69 64 64 6c 65 72 } //1 taskkill /FI "IMAGENAME eq fiddler
		$a_01_9 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 77 69 72 65 73 68 61 72 6b } //1 taskkill /FI "IMAGENAME eq wireshark
		$a_01_10 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 69 64 61 2a } //1 taskkill /FI "IMAGENAME eq ida*
		$a_01_11 = {73 63 20 73 74 6f 70 20 48 54 54 50 44 65 62 75 67 67 65 72 50 72 6f } //1 sc stop HTTPDebuggerPro
		$a_01_12 = {73 63 20 73 74 6f 70 20 77 69 72 65 73 68 61 72 6b } //1 sc stop wireshark
		$a_01_13 = {45 6e 74 65 72 20 4c 69 63 65 6e 73 65 20 3a } //1 Enter License :
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}