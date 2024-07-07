
rule Trojan_BAT_njRAT_RDJ_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {39 39 32 30 41 42 38 33 2d 30 33 35 38 2d 34 44 34 37 2d 39 37 31 35 2d 36 30 43 35 31 35 41 37 31 46 37 44 } //1 9920AB83-0358-4D47-9715-60C515A71F7D
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_01_5 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 CloseHandle
		$a_01_6 = {47 65 74 49 4c 47 65 6e 65 72 61 74 6f 72 } //1 GetILGenerator
		$a_01_7 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_8 = {49 4c 47 65 6e 65 72 61 74 6f 72 } //1 ILGenerator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}