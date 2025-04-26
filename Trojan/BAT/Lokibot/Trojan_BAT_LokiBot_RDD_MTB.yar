
rule Trojan_BAT_LokiBot_RDD_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 28 ?? ?? ?? ?? 25 26 69 5d 91 02 08 91 61 d2 6f 1e 00 00 0a 08 1f 10 28 ?? ?? ?? ?? 58 0c 08 02 28 } //2
		$a_01_1 = {53 65 74 4c 61 73 74 45 72 72 6f 72 } //1 SetLastError
		$a_01_2 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 CloseHandle
		$a_01_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_5 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_6 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_7 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 kernel32.dll
		$a_01_8 = {75 73 65 72 33 32 2e 64 6c 6c } //1 user32.dll
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}