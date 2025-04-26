
rule VirTool_Win32_CeeInject_JJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.JJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 84 1b 00 00 00 8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 0f 85 e5 ff ff ff } //2
		$a_01_1 = {8b 40 78 83 65 fc 00 03 c1 8b 78 1c 8b 58 24 8b 70 20 8b 40 18 03 f9 03 d9 03 f1 } //1
		$a_01_2 = {8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 04 24 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}