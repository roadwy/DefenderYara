
rule VirTool_Win32_VBInject_WX{
	meta:
		description = "VirTool:Win32/VBInject.WX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 43 61 6c 6c 45 6e 67 69 6e 65 } //1 ProcCallEngine
		$a_03_1 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0 } //1
		$a_03_2 = {e7 aa f5 00 01 00 00 c2 90 09 07 00 4a c2 6c ?? ff fc 90 90 } //1
		$a_03_3 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 [0-0a] f5 00 00 00 00 ?? 1c } //1
		$a_03_4 = {f5 00 00 00 00 f5 ff ff ff ff 04 ?? f7 fe 8e 00 00 00 00 10 00 80 08 04 ?? f7 94 08 00 ?? ?? 94 08 00 ?? ?? 5e ?? ?? ?? ?? 71 ?? f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}