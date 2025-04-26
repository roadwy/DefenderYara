
rule VirTool_Win32_VBInject_YAK_MTB{
	meta:
		description = "VirTool:Win32/VBInject.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fc 83 c0 20 ff 45 38 ff 4d 38 83 e8 21 83 04 24 00 f8 39 08 d9 fa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}