
rule VirTool_Win32_VBInject_AHD_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 f6 e7 1e 00 90 02 20 05 60 18 23 00 90 02 20 39 41 04 90 02 20 68 cd 7b 34 00 90 02 20 58 90 02 20 05 80 84 1e 00 90 02 20 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHD_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 18 00 00 00 90 02 40 64 8b 00 90 02 40 8b 40 30 90 02 40 5b 90 02 40 02 58 02 90 02 40 ff e3 90 00 } //1
		$a_03_1 = {83 f9 00 75 90 02 40 ff e0 90 00 } //1
		$a_03_2 = {81 eb 00 10 00 00 90 02 40 53 90 02 40 6a 00 90 02 40 6a 00 90 02 40 ff 72 68 90 02 40 ff 72 6c 90 02 40 ff 72 70 90 02 40 ff 72 74 90 02 40 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}