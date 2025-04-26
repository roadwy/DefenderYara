
rule VirTool_Win32_CeeInject_OW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OW!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b f0 33 d6 03 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 0a } //1
		$a_01_1 = {55 8b ec 6a 04 68 00 10 00 00 e8 41 cd ff ff 50 6a 00 ff 15 04 70 42 00 a3 e8 ad 42 00 5d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}