
rule VirTool_Win32_Ceeinject_NH_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 69 62 38 67 6e 6a 6a 6b 6c 6c 6c 6c 6f 2e 64 6c 6c } //1 %ib8gnjjkllllo.dll
		$a_01_1 = {8b d8 83 e3 01 f7 db 81 e3 20 83 b8 ed d1 e8 33 c3 4f 79 ec } //1
		$a_01_2 = {0f b6 39 4a 6a 07 33 c7 5f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}