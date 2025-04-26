
rule VirTool_Win32_CeeInject_RR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad c2 10 00 8b 46 14 8b 40 0c 8b 08 33 43 48 c2 08 00 } //2
		$a_03_1 = {89 44 24 04 89 04 24 3b 43 4c 0f 86 ?? ?? ?? ff c1 e8 0a 25 ff 00 00 00 3b 43 50 0f 83 ?? ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}