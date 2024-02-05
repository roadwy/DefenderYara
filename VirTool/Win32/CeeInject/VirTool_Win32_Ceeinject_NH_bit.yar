
rule VirTool_Win32_Ceeinject_NH_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 69 62 38 67 6e 6a 6a 6b 6c 6c 6c 6c 6f 2e 64 6c 6c } //01 00 
		$a_01_1 = {8b d8 83 e3 01 f7 db 81 e3 20 83 b8 ed d1 e8 33 c3 4f 79 ec } //01 00 
		$a_01_2 = {0f b6 39 4a 6a 07 33 c7 5f } //00 00 
	condition:
		any of ($a_*)
 
}