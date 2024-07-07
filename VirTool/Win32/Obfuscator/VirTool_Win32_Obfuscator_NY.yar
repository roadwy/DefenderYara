
rule VirTool_Win32_Obfuscator_NY{
	meta:
		description = "VirTool:Win32/Obfuscator.NY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 0c 68 ff ff 0f 00 90 18 ff d0 90 00 } //2
		$a_01_1 = {68 6a d9 3f 2e } //1
		$a_01_2 = {68 9d 73 e8 f2 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}