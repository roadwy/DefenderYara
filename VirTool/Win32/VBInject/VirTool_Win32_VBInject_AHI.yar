
rule VirTool_Win32_VBInject_AHI{
	meta:
		description = "VirTool:Win32/VBInject.AHI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 b0 00 8d 45 b0 50 6a 08 8d 45 e4 50 ff 75 0c 6a ff e8 } //1
		$a_01_1 = {68 10 00 00 00 8b c4 50 8d 44 24 0c 50 b9 ad 14 4a 73 ff d1 59 0b c0 78 0c 8b 44 24 04 8b 00 ff a0 40 00 00 00 5a 03 e1 52 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_AHI_2{
	meta:
		description = "VirTool:Win32/VBInject.AHI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 6e 00 49 00 4a 00 69 00 20 00 00 00 44 00 1c 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 70 00 49 00 52 00 69 00 66 00 4f 00 72 00 6d 00 20 00 6c 00 54 00 64 00 20 00 00 00 38 00 14 00 01 00 } //1
		$a_01_1 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 48 00 50 00 2c 00 20 00 49 00 4e 00 63 00 2e 00 20 00 00 00 4c 00 22 00 01 00 4c 00 65 00 67 00 61 00 6c 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 73 00 00 00 00 00 4c 00 69 00 54 00 43 00 4f 00 69 00 6e 00 20 00 } //1
		$a_01_2 = {70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 20 00 00 00 00 00 3c 00 1a 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 79 00 41 00 48 00 4f 00 6f 00 2c 00 20 00 69 00 4e 00 63 00 2e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}