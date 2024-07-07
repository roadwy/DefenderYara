
rule Trojan_BAT_AntiVm_NA_MTB{
	meta:
		description = "Trojan:BAT/AntiVm.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 7c 00 00 0a 03 07 6f 7c 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 15 00 00 0a 32 e1 } //10
		$a_81_1 = {64 72 69 76 65 72 73 5c 76 6d 6d 6f 75 73 65 2e 73 79 73 } //1 drivers\vmmouse.sys
		$a_81_2 = {64 72 69 76 65 72 73 5c 76 6d 68 67 66 73 2e 73 79 73 } //1 drivers\vmhgfs.sys
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4f 6c 6c 79 44 62 67 2e 65 78 65 } //1 taskkill /f /im OllyDbg.exe
		$a_81_4 = {73 63 20 73 74 6f 70 20 77 69 72 65 73 68 61 72 6b } //1 sc stop wireshark
		$a_81_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 48 54 54 50 44 65 62 75 67 67 65 72 2e 65 78 65 } //1 taskkill /f /im HTTPDebugger.exe
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}