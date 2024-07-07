
rule TrojanDropper_Win32_SiBrov_A{
	meta:
		description = "TrojanDropper:Win32/SiBrov.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc 4e f7 a5 90 01 04 c1 ea 90 01 01 8a c2 8a ca c0 e0 90 01 01 02 c8 8b 85 90 01 04 02 c9 2a c1 04 90 01 01 88 06 8b c2 89 85 90 01 04 85 c0 90 00 } //3
		$a_01_1 = {47 65 74 46 69 6c 65 53 69 7a 65 } //1 GetFileSize
		$a_01_2 = {52 65 61 64 46 69 6c 65 } //1 ReadFile
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
		$a_01_4 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //1 GetModuleHandleA
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}