
rule VirTool_Win32_Vbcrypt_EA{
	meta:
		description = "VirTool:Win32/Vbcrypt.EA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 65 6b } //1 Devek
		$a_01_1 = {78 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 xwUnmapViewOfSection
		$a_01_2 = {66 69 6c 65 58 } //1 fileX
		$a_01_3 = {7a 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 zreateProcessA
		$a_01_4 = {7a 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 ztWriteVirtualMemory
		$a_01_5 = {5f 5f 76 62 61 7a 6f 70 79 42 79 74 65 73 } //1 __vbazopyBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}