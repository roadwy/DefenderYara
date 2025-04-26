
rule VirTool_Win32_Obfuscator_SL{
	meta:
		description = "VirTool:Win32/Obfuscator.SL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 c7 8d 8c 08 22 10 00 00 33 cf } //1
		$a_01_1 = {5e f7 f6 81 fa 83 00 00 00 0f } //1
		$a_01_2 = {be c1 d0 ff ff 81 fe dc cf ff ff 0f } //1
		$a_01_3 = {81 fe c2 cf ff ff 0f } //1
		$a_01_4 = {b8 40 09 98 08 } //1
		$a_01_5 = {be 92 ac f7 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}