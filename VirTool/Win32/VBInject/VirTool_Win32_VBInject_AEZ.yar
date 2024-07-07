
rule VirTool_Win32_VBInject_AEZ{
	meta:
		description = "VirTool:Win32/VBInject.AEZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {be 74 23 11 00 c7 43 34 04 00 00 00 5f 39 73 34 0f 8f 22 01 00 00 dd 05 f0 10 40 00 51 51 dd 1c 24 e8 7c ab fe ff dd d8 51 51 d9 e8 dd 1c 24 } //1
		$a_03_1 = {bf 70 07 31 c7 c7 81 90 01 02 00 00 70 07 31 ca 8b 48 54 c7 81 90 01 02 00 00 02 6e d8 ff 8b 48 54 c7 81 90 01 02 00 00 20 75 d5 e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}