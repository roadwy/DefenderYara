
rule VirTool_Win32_CeeInject_CW{
	meta:
		description = "VirTool:Win32/CeeInject.CW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 55 fc 8b 45 f8 0f b7 4e 06 83 45 f0 28 40 89 45 f8 3b c1 7c bf } //1
		$a_01_1 = {8b 4e 54 8b 55 08 6a 00 51 8b 4d 0c 53 52 89 45 fc 51 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}