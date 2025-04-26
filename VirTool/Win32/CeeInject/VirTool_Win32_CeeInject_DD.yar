
rule VirTool_Win32_CeeInject_DD{
	meta:
		description = "VirTool:Win32/CeeInject.DD,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 49 0c 8a 04 01 2c ?? 34 ?? 3c } //10
		$a_03_1 = {8b 4d fc 66 8b 09 b8 ?? ?? 00 00 [0-10] 66 2b c8 [0-70] b8 ?? ?? 00 00 66 33 c8 b8 ?? ?? 00 00 66 3b c8 0f 85 ?? ?? ff ff } //1
		$a_03_2 = {8b 4d fc 66 8b 09 b8 ?? ?? 00 00 66 2b c8 b8 ?? ?? 00 00 66 33 c8 66 3b cb 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}