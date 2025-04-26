
rule Trojan_Win64_CryptInject_RHD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {62 72 6f 77 73 65 72 2e 74 6f 6f 6c 62 61 72 73 } //1 browser.toolbars
		$a_01_1 = {65 78 74 65 6e 73 69 6f 6e 73 2e 74 6f 72 6c 61 75 6e 63 68 65 72 } //1 extensions.torlauncher
		$a_01_2 = {68 74 74 70 3a 2f 2f } //1 http://
		$a_01_3 = {73 62 63 32 7a 76 32 71 6e 7a 35 76 75 62 77 74 78 33 61 6f 62 66 70 6b 65 61 6f 36 6c 34 69 67 6a 65 67 6d 33 78 78 37 74 6b 35 73 75 71 68 6a 6b 70 35 6a 78 74 71 64 2e 6f 6e 69 6f 6e 2f } //1 sbc2zv2qnz5vubwtx3aobfpkeao6l4igjegm3xx7tk5suqhjkp5jxtqd.onion/
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_5 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 } //1 Process32FirstW
		$a_01_6 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 } //1 Process32NextW
		$a_01_7 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
		$a_03_9 = {50 45 00 00 64 86 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 00 00 ?? ?? 00 00 ?? ?? 00 00 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*2) >=11
 
}