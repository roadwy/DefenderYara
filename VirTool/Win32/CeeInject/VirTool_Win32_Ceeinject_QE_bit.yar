
rule VirTool_Win32_Ceeinject_QE_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.QE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {dc ca 50 d8 c3 d3 d8 58 d8 c2 d8 c4 d9 f7 df 5d fe 90 01 01 ed 90 00 } //1
		$a_03_1 = {60 64 8b 1d 18 00 00 00 89 1d 90 01 04 61 90 02 06 8b 90 01 01 30 90 02 12 8b 90 01 01 0c 90 02 12 8b 90 01 01 1c 90 02 12 8b 90 01 01 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}