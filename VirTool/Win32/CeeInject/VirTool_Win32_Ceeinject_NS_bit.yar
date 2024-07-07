
rule VirTool_Win32_Ceeinject_NS_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d0 8b 85 90 01 04 03 85 90 01 04 8a 95 90 01 04 8a 08 e8 90 01 04 8b 8d 90 01 04 03 8d 90 01 04 88 01 33 d2 74 90 00 } //1
		$a_01_1 = {33 33 31 35 33 31 35 24 } //1 3315315$
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}