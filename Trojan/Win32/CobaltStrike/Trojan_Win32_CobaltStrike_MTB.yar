
rule Trojan_Win32_CobaltStrike_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {61 72 74 69 66 61 63 74 36 34 62 69 67 2e 64 6c 6c } //1 artifact64big.dll
		$a_01_1 = {61 72 74 69 66 61 63 74 33 32 62 69 67 2e 64 6c 6c } //1 artifact32big.dll
		$a_01_2 = {67 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 gkernel32.dll
		$a_01_3 = {4b 5b 5a 4b 4b 5c 4f 4b 4d } //1 K[ZKK\OKM
		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_5 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_7 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_8 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //1 GetCommandLineA
		$a_01_9 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 } //1 GetCommandLineW
		$a_01_10 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}