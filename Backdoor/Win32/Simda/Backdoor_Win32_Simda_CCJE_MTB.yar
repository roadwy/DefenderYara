
rule Backdoor_Win32_Simda_CCJE_MTB{
	meta:
		description = "Backdoor:Win32/Simda.CCJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c 6f 70 65 72 61 2e 65 78 65 7c 6a 61 76 61 2e 65 78 65 7c 6a 61 76 61 77 2e 65 78 65 7c 65 78 70 6c 6f 72 65 72 2e 65 78 65 7c 69 73 63 6c 69 65 6e 74 2e 65 78 65 7c 69 6e 74 70 72 6f 2e 65 78 65 } //10 iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe
		$a_01_1 = {7b 42 6f 74 56 65 72 3a } //10 {BotVer:
		$a_01_2 = {7b 55 73 65 72 6e 61 6d 65 3a } //5 {Username:
		$a_01_3 = {7b 50 72 6f 63 65 73 73 6f 72 3a } //5 {Processor:
		$a_01_4 = {7b 4c 61 6e 67 75 61 67 65 3a } //5 {Language:
		$a_01_5 = {7b 53 63 72 65 65 6e 3a } //5 {Screen:
		$a_01_6 = {6b 61 73 70 65 72 73 6b 79 } //5 kaspersky
		$a_01_7 = {65 73 65 74 2e 63 6f 6d } //5 eset.com
		$a_01_8 = {61 6e 74 69 2d 6d 61 6c 77 61 72 65 } //5 anti-malware
		$a_01_9 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e } //5 software\microsoft\windows nt\currentversion\winlogon
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=60
 
}