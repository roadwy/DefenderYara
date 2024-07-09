
rule VirTool_Win32_Injector_CJ{
	meta:
		description = "VirTool:Win32/Injector.CJ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 65 fc 00 b8 01 00 00 00 0f 3f 07 0b c7 45 fc ff ff ff ff c7 45 fc fe ff ff ff } //10
		$a_01_1 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07 } //10
		$a_03_2 = {c7 45 e4 58 59 59 59 6a 04 8d 45 e4 50 8d 45 78 50 e8 ?? ?? 00 00 c7 45 e4 59 50 00 00 } //1
		$a_01_3 = {c7 45 78 58 59 59 59 b8 59 50 00 00 66 11 45 7c } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}