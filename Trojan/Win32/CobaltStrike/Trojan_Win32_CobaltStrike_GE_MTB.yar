
rule Trojan_Win32_CobaltStrike_GE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 41 65 73 44 65 63 72 79 70 74 42 79 45 43 42 } //1 main.AesDecryptByECB
		$a_01_1 = {6d 61 69 6e 2e 50 4b 43 53 37 55 4e 50 61 64 64 69 6e 67 } //1 main.PKCS7UNPadding
		$a_01_2 = {6d 61 69 6e 2e 63 6c 6f 73 65 57 69 6e 64 6f 77 73 } //1 main.closeWindows
		$a_01_3 = {72 75 6e 74 69 6d 65 2e 73 79 73 52 65 73 65 72 76 65 } //1 runtime.sysReserve
		$a_01_4 = {72 75 6e 74 69 6d 65 2e 62 61 64 63 74 78 74 } //1 runtime.badctxt
		$a_01_5 = {72 75 6e 74 69 6d 65 2e 61 6c 6c 67 61 64 64 } //1 runtime.allgadd
		$a_01_6 = {72 75 6e 74 69 6d 65 2e 74 72 61 63 65 53 68 75 74 74 69 6e 67 44 6f 77 6e } //1 runtime.traceShuttingDown
		$a_01_7 = {72 75 6e 74 69 6d 65 2e 74 72 61 63 65 4c 6f 63 6b 65 72 2e 47 6f 53 63 68 65 64 } //1 runtime.traceLocker.GoSched
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}