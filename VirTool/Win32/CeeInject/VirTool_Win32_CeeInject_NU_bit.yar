
rule VirTool_Win32_CeeInject_NU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 14 41 8b 85 90 01 04 0f af 85 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 03 c1 03 d0 a1 90 01 04 03 85 90 01 04 88 10 90 00 } //1
		$a_03_1 = {8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d 90 01 04 97 8b d9 93 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}