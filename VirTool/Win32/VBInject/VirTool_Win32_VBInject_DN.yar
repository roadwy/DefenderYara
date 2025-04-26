
rule VirTool_Win32_VBInject_DN{
	meta:
		description = "VirTool:Win32/VBInject.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {f5 fe 00 00 00 c2 04 60 ff 9d e7 aa 04 60 ff 9d fb 12 } //1
		$a_03_1 = {e7 f5 4d 5a 00 00 cc 1c ?? ?? ff } //1
		$a_03_2 = {f5 50 45 00 00 cc 1c ?? ?? ff } //1
		$a_03_3 = {f5 2a 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 56 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 4d 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 57 } //1
		$a_03_4 = {f3 e8 00 2b ?? ?? 6c ?? ff } //1
		$a_03_5 = {bc 02 f5 f8 00 00 00 aa f5 28 00 00 00 08 08 00 8a ?? ?? b2 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}