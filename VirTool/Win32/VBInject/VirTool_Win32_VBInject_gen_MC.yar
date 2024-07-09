
rule VirTool_Win32_VBInject_gen_MC{
	meta:
		description = "VirTool:Win32/VBInject.gen!MC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {fb 12 fc 0d 04 ?? ?? fc 22 80 ?? ?? fc a0 } //2
		$a_03_1 = {4a f5 b8 0b 00 00 db 1c ?? 00 6c 70 ff 6c 6c ff 2a 31 70 ff f5 00 00 00 00 } //2
		$a_03_2 = {6b 72 ff e7 80 10 00 4a c2 f5 01 00 00 00 aa 6c 10 00 4d 5c ff 08 40 04 ?? ?? 0a ?? 00 10 00 } //1
		$a_03_3 = {80 0c 00 2e ?? ff 40 5e ?? 00 04 00 71 ?? ff 2d ?? ff f5 00 00 00 00 f5 00 00 00 00 6c ?? ff 6c ?? ff 6c ?? ff 0a ?? 00 14 00 (3c 14|14) } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}