
rule VirTool_Win32_VBInject_AHD_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 f6 e7 1e 00 [0-20] 05 60 18 23 00 [0-20] 39 41 04 [0-20] 68 cd 7b 34 00 [0-20] 58 [0-20] 05 80 84 1e 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHD_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 18 00 00 00 [0-40] 64 8b 00 [0-40] 8b 40 30 [0-40] 5b [0-40] 02 58 02 [0-40] ff e3 } //1
		$a_03_1 = {83 f9 00 75 [0-40] ff e0 } //1
		$a_03_2 = {81 eb 00 10 00 00 [0-40] 53 [0-40] 6a 00 [0-40] 6a 00 [0-40] ff 72 68 [0-40] ff 72 6c [0-40] ff 72 70 [0-40] ff 72 74 [0-40] 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}