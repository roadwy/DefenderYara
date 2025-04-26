
rule VirTool_Win32_VBInject_IP{
	meta:
		description = "VirTool:Win32/VBInject.IP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 08 8b 45 08 8b 80 ?? ?? 00 00 8b 95 ?? ?? ff ff 66 8b 04 50 66 25 ff 00 66 33 c8 } //1
		$a_03_1 = {eb 04 83 65 ?? 00 8d 45 ?? 50 66 b9 c3 00 } //1
		$a_00_2 = {65 00 78 00 65 00 20 00 73 00 69 00 68 00 54 00 } //1 exe sihT
		$a_00_3 = {2a 00 4c 00 41 00 55 00 54 00 52 00 49 00 56 00 2a 00 } //1 *LAUTRIV*
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}