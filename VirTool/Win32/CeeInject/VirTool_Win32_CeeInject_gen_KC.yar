
rule VirTool_Win32_CeeInject_gen_KC{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 00 00 ba 30 75 00 00 e8 90 09 02 00 b9 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 68 ?? 61 00 00 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_gen_KC_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 00 89 84 bd ?? fb ff ff 8b 84 9d 90 1b 00 fb ff ff 03 84 bd 90 1b 00 fb ff ff 25 ff 00 00 80 79 } //1
		$a_01_1 = {0f b6 04 02 03 3e 03 c7 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b f8 } //1
		$a_03_2 = {0f b6 04 02 8b 55 ?? 8b 94 95 ?? ?? ff ff 03 55 ?? 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } //1
		$a_03_3 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 (32 94 85|8a 84 85) ?? fb ff ff 90 09 1c 00 8b 84 9d ?? fb ff ff 03 84 bd ?? fb ff ff } //1
		$a_03_4 = {6a 1f 6a 20 8d 85 ?? ?? ff ff b9 ?? ?? 00 00 ba ?? ?? 00 00 } //10
		$a_01_5 = {50 6a 40 68 8d 22 00 00 8b 45 f8 50 e8 } //10
		$a_03_6 = {6a 1f 6a 20 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 ?? e8 } //10
		$a_03_7 = {50 6a 20 ba ?? ?? ?? ?? b9 1f 00 00 00 b8 ?? ?? 00 00 e8 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*10+(#a_01_5  & 1)*10+(#a_03_6  & 1)*10+(#a_03_7  & 1)*10) >=11
 
}