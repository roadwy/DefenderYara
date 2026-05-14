
rule Trojan_Win32_FlyStudio_PGC_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 WScript.Shell
		$a_01_1 = {63 6f 70 79 2e 64 61 74 } //1 copy.dat
		$a_01_2 = {53 63 72 69 70 74 2e 69 6e 69 } //1 Script.ini
		$a_01_3 = {4c 65 61 67 75 65 20 6f 66 20 4c 65 67 65 6e 64 73 2e 65 78 65 } //1 League of Legends.exe
		$a_01_4 = {31 38 30 2e 31 30 31 2e 37 35 2e 35 38 } //1 180.101.75.58
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 } //1 CreateShortcut
		$a_01_7 = {5c 58 4f 2e 64 6c 6c } //1 \XO.dll
		$a_01_8 = {64 61 74 61 2e 64 61 74 } //1 data.dat
		$a_01_9 = {61 63 63 6f 75 6e 74 00 4c 6f 67 69 6e 00 70 61 73 73 77 6f 72 64 } //1 捡潣湵t潌楧n慰獳潷摲
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}