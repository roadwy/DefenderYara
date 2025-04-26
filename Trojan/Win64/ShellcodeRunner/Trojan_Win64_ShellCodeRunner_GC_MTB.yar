
rule Trojan_Win64_ShellCodeRunner_GC_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 41 65 73 44 65 63 72 79 70 74 } //1 main.AesDecrypt
		$a_01_1 = {6d 61 69 6e 2e 48 65 78 53 74 72 54 6f 42 79 74 65 73 } //1 main.HexStrToBytes
		$a_01_2 = {6d 61 69 6e 2e 69 73 4e 6f 6e 43 68 69 6e 65 73 65 } //1 main.isNonChinese
		$a_01_3 = {6d 61 69 6e 2e 69 73 4e 6f 6e 43 68 69 6e 65 73 65 2e 64 65 66 65 72 77 72 61 70 31 } //1 main.isNonChinese.deferwrap1
		$a_01_4 = {6d 61 69 6e 2e 69 73 50 79 74 68 6f 6e 49 6e 43 44 72 69 76 65 } //1 main.isPythonInCDrive
		$a_01_5 = {6d 61 69 6e 2e 6d 61 69 6e } //1 main.main
		$a_01_6 = {6d 61 69 6e 2e 69 73 43 50 55 4c 6f 77 } //1 main.isCPULow
		$a_01_7 = {6d 61 69 6e 2e 48 69 64 65 43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 } //1 main.HideConsoleWindow
		$a_01_8 = {6d 61 69 6e 2e 48 65 78 50 61 72 73 65 4b 65 79 } //1 main.HexParseKey
		$a_01_9 = {2f 53 68 65 6c 6c 43 6f 64 65 2f 53 68 65 6c 6c 43 6f 64 65 } //1 /ShellCode/ShellCode
		$a_01_10 = {4c 61 7a 79 44 4c 4c } //1 LazyDLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}