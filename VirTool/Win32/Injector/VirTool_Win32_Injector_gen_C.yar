
rule VirTool_Win32_Injector_gen_C{
	meta:
		description = "VirTool:Win32/Injector.gen!C,SIGNATURE_TYPE_PEHSTR,68 00 67 00 05 00 00 "
		
	strings :
		$a_01_0 = {03 cb 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 33 c0 8a 84 0d 00 ff ff ff 33 d0 8b 8d e8 fe ff ff 03 8d f8 fe ff ff 88 11 e9 } //100
		$a_01_1 = {43 75 72 72 65 6e 74 55 73 65 72 } //1 CurrentUser
		$a_01_2 = {76 6d 77 61 72 65 } //1 vmware
		$a_01_3 = {73 61 6e 64 62 6f 78 } //1 sandbox
		$a_01_4 = {53 77 61 70 4d 6f 75 73 65 42 75 74 74 6f 6e 73 } //1 SwapMouseButtons
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=103
 
}