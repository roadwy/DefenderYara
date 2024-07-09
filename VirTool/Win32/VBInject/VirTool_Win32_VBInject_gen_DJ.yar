
rule VirTool_Win32_VBInject_gen_DJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!DJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {aa 08 08 00 8f 28 01 90 09 0a 00 94 ?? ?? 1c 00 94 90 1b 01 10 00 } //1
		$a_01_1 = {f5 44 00 00 00 08 08 00 8f 74 01 f5 07 00 01 00 08 08 00 } //1
		$a_03_2 = {4a c2 f5 01 00 00 00 aa [0-1f] e7 fb 13 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_VBInject_gen_DJ_2{
	meta:
		description = "VirTool:Win32/VBInject.gen!DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 03 8b 48 0c 8b 45 c0 66 0f b6 0c 11 66 33 0c 70 } //1
		$a_01_1 = {3a 00 3b 00 54 00 4d 00 56 00 5a 00 4d 00 53 00 } //1 :;TMVZMS
		$a_02_2 = {8b c4 83 c0 04 93 8b e3 8b 5b fc 81 eb ?? ?? 40 00 87 dd 83 bd ?? ?? 40 00 01 0f 84 ?? ?? 00 00 80 bd ?? ?? 40 00 90 90 74 ?? 8d 85 ?? ?? 40 00 50 ff 95 ?? ?? 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}