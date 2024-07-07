
rule VirTool_Win32_VBInject_gen_EP{
	meta:
		description = "VirTool:Win32/VBInject.gen!EP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {6c 68 fe 6c 5c fe aa 71 b0 fd } //1
		$a_01_1 = {6c 40 fe 6c 34 fe aa 71 5c fd } //1
		$a_01_2 = {6c 54 fe 6c 48 fe aa 71 7c fd } //1
		$a_01_3 = {6c 58 fe 6c 4c fe aa 71 9c fd } //1
		$a_01_4 = {f5 07 00 01 00 } //1
		$a_01_5 = {f3 c3 00 fc 0d } //1
		$a_03_6 = {6c 68 ff f5 28 00 00 00 aa 5e 90 01 04 aa f5 2c 00 00 00 04 0c ff a3 90 00 } //2
		$a_01_7 = {4d 5a 52 45 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*2+(#a_01_7  & 1)*1) >=3
 
}