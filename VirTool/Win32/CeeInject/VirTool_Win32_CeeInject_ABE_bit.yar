
rule VirTool_Win32_CeeInject_ABE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c1 03 d0 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 84 15 ?? ?? ?? ?? 88 84 1d ?? ?? ?? ?? 88 8c 15 ?? ?? ?? ?? 0f b6 84 1d ?? ?? ?? ?? 0f b6 c9 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 84 0d ?? ?? ?? ?? 30 04 3e 46 3b 75 0c 72 91 } //1
		$a_01_1 = {8b c6 83 e0 03 8a 44 05 08 30 04 0e 46 3b f2 72 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}