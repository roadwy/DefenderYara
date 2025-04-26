
rule VirTool_Win32_Bruterat_D{
	meta:
		description = "VirTool:Win32/Bruterat.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 50 3c 8d 4a c0 81 f9 bf 03 00 00 77 e8 81 3c 10 ?? ?? 00 00 75 df } //1
		$a_03_1 = {83 e8 01 66 81 38 4d 5a 75 f6 8b 50 ?? 8d 4a c0 81 f9 bf 03 00 00 77 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}