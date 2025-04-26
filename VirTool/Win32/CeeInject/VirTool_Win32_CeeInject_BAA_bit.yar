
rule VirTool_Win32_CeeInject_BAA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {bf 40 4b 4c 00 8d 64 24 00 e8 20 1a 00 00 0f af f0 4f 75 f5 } //1
		$a_01_1 = {81 3c c7 2e 72 65 6c } //1
		$a_03_2 = {b8 81 80 80 80 f7 e9 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 c2 02 c1 30 81 ?? ?? ?? ?? 41 81 f9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}