
rule VirTool_Win32_VBInject_WX{
	meta:
		description = "VirTool:Win32/VBInject.WX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 43 61 6c 6c 45 6e 67 69 6e 65 } //1 ProcCallEngine
		$a_03_1 = {fb 12 fc 0d 6c 90 01 02 80 90 01 02 fc a0 90 00 } //1
		$a_03_2 = {e7 aa f5 00 01 00 00 c2 90 09 07 00 4a c2 6c 90 01 01 ff fc 90 90 90 00 } //1
		$a_03_3 = {f4 02 eb 6b 90 01 01 ff eb fb cf e8 c4 90 02 0a f5 00 00 00 00 90 01 01 1c 90 00 } //1
		$a_03_4 = {f5 00 00 00 00 f5 ff ff ff ff 04 90 01 01 f7 fe 8e 00 00 00 00 10 00 80 08 04 90 01 01 f7 94 08 00 90 01 02 94 08 00 90 01 02 5e 90 01 04 71 90 01 01 f6 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}