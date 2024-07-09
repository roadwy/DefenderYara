
rule VirTool_Win32_DelfInject_gen_DD{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4a 81 ca 00 ff ff ff 42 32 84 95 ?? ?? ff ff 8b 55 fc 88 02 } //1
		$a_01_1 = {68 7c 66 00 00 8b 45 f8 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}