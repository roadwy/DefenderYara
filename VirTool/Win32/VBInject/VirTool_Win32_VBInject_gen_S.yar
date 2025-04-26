
rule VirTool_Win32_VBInject_gen_S{
	meta:
		description = "VirTool:Win32/VBInject.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {75 05 89 75 ?? eb 46 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 e6 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 d1 } //1
		$a_03_1 = {75 08 89 b5 ?? ?? ff ff eb 49 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 e3 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 ce } //1
		$a_03_2 = {f6 c4 01 74 07 ba ?? ?? 40 00 eb 15 f6 c4 02 74 07 ba ?? ?? 40 00 eb 09 a8 40 74 14 } //3
		$a_01_3 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 45 00 6e 00 75 00 6d 00 } //3 SYSTEM\ControlSet001\Services\Disk\Enum
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3+(#a_01_3  & 1)*3) >=7
 
}