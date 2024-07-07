
rule VirTool_Win32_Injector_FW{
	meta:
		description = "VirTool:Win32/Injector.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 64 65 62 6c 6f 78 5c 5f 5f 5f 73 74 75 62 7a 5c 47 63 63 61 6c 61 78 79 5c 6d 61 69 6e 2e 63 70 70 } //2 codeblox\___stubz\Gccalaxy\main.cpp
		$a_03_1 = {b0 00 00 00 8d 85 90 01 02 ff ff 05 96 00 00 00 89 44 24 04 8b 85 90 01 02 ff ff 89 04 24 8b 85 90 01 02 ff ff ff d0 90 09 02 00 89 90 90 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}