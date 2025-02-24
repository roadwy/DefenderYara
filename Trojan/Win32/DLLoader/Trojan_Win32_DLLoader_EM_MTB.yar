
rule Trojan_Win32_DLLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/DLLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba 4b 00 00 00 8b 0b 89 08 8b 4c 13 fc 89 4c 10 fc 8d 78 04 83 e7 fc 29 f8 29 c3 01 c2 83 e2 fc 89 d0 c1 e8 02 } //5
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 5f 68 6f 6f 6b 65 64 } //1 CreateMutexA_hooked
		$a_01_2 = {43 72 65 61 74 65 49 41 54 48 6f 6f 6b } //1 CreateIATHook
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 22 69 65 78 20 28 67 63 20 28 27 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 } //1 powershell -command "iex (gc ('C:\ProgramData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}