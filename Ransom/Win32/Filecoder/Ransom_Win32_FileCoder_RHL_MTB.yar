
rule Ransom_Win32_FileCoder_RHL_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.RHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 6b 65 79 } //1 seckey
		$a_01_1 = {70 75 62 6b 65 79 } //1 pubkey
		$a_01_2 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 57 } //1 GetLogicalDriveStringsW
		$a_01_3 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_5 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_6 = {54 68 72 65 61 64 33 32 4e 65 78 74 } //1 Thread32Next
		$a_01_7 = {4d 6f 64 75 6c 65 33 32 4e 65 78 74 } //1 Module32Next
		$a_03_8 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 04 02 00 00 c2 01 00 00 00 00 00 91 4a 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*2) >=10
 
}