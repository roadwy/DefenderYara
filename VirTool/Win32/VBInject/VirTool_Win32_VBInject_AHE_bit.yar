
rule VirTool_Win32_VBInject_AHE_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 56 f7 04 00 90 02 20 58 90 02 20 05 00 09 3d 00 90 02 20 39 41 04 90 02 20 68 cd 7b 34 00 90 02 20 58 90 02 20 05 80 84 1e 00 90 02 20 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHE_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 90 01 02 00 00 90 02 40 41 90 02 40 8b 53 2c 90 02 40 31 ca 90 02 40 83 fa 00 75 90 00 } //1
		$a_03_1 = {83 fa 00 75 90 02 40 89 ce 90 02 40 6a 78 90 02 40 58 90 02 40 31 d2 90 02 40 48 90 02 40 48 90 02 40 48 90 02 40 48 90 02 40 33 14 03 90 02 40 e8 90 01 03 ff 90 02 40 52 90 02 40 83 f8 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}