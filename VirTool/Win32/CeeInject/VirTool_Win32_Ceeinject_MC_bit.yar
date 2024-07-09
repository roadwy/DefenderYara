
rule VirTool_Win32_Ceeinject_MC_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.MC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 7c 0f 8b c1 99 6a ?? 5b f7 fb 8a 44 15 ?? 30 04 39 41 3b ce 72 e8 } //1
		$a_03_1 = {03 ce 8b c1 ff 70 ?? 8b 48 ?? 8b 40 ?? 03 05 ?? ?? ?? ?? 03 ce 51 50 ff d3 0f b7 47 ?? 45 3b e8 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}