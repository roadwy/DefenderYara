
rule VirTool_Win32_Ceeinject_NJ_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c0 2b 03 f7 d8 f8 83 db 90 01 01 f7 d8 f8 83 d8 90 01 01 c1 c8 90 01 01 d1 c0 31 c8 f8 83 d8 01 8d 08 c1 c1 90 01 01 d1 c9 f7 d9 50 8f 07 83 ef 90 01 01 f8 83 d6 90 01 01 68 90 00 } //1
		$a_03_1 = {68 04 07 00 00 5e 8d 1d 90 01 04 53 8d 0d 90 01 04 51 8d 05 90 01 04 50 8d 15 90 01 04 52 8d 15 90 01 04 52 8d 0d 90 01 04 83 c1 90 01 01 ff 11 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}