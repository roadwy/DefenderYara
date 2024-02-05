
rule VirTool_Win32_Ceeinject_MC_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.MC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c9 7c 0f 8b c1 99 6a 90 01 01 5b f7 fb 8a 44 15 90 01 01 30 04 39 41 3b ce 72 e8 90 00 } //01 00 
		$a_03_1 = {03 ce 8b c1 ff 70 90 01 01 8b 48 90 01 01 8b 40 90 01 01 03 05 90 01 04 03 ce 51 50 ff d3 0f b7 47 90 01 01 45 3b e8 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}