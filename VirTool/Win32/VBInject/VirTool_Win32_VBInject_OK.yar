
rule VirTool_Win32_VBInject_OK{
	meta:
		description = "VirTool:Win32/VBInject.OK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 8d 45 e8 ff 75 d0 56 6a 08 50 6a 04 68 80 01 00 00 } //1
		$a_01_1 = {8b 7d 08 8b d0 f7 da ff 37 1b d2 f7 da 56 89 95 78 ff ff ff } //1
		$a_01_2 = {6a 04 8d 45 8c 5b c7 45 8c 58 59 59 59 53 50 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}