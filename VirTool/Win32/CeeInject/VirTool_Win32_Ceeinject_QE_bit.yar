
rule VirTool_Win32_Ceeinject_QE_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.QE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {dc ca 50 d8 c3 d3 d8 58 d8 c2 d8 c4 d9 f7 df 5d fe ?? ed } //1
		$a_03_1 = {60 64 8b 1d 18 00 00 00 89 1d ?? ?? ?? ?? 61 [0-06] 8b ?? 30 [0-12] 8b ?? 0c [0-12] 8b ?? 1c [0-12] 8b ?? 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}