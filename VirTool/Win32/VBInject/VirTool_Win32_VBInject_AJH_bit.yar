
rule VirTool_Win32_VBInject_AJH_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 41 41 41 41 [0-30] 46 [0-30] 8b 17 [0-30] 31 f2 [0-30] 75 } //1
		$a_03_1 = {bb f4 cb 6c 00 [0-30] 81 c3 59 8e 23 00 [0-30] 48 [0-30] 39 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_AJH_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AJH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 c0 10 00 00 90 09 20 00 75 90 09 20 00 39 18 [0-20] 00 48 } //1
		$a_03_1 = {b9 41 41 41 41 [0-30] 46 [0-30] ff 37 [0-30] 31 34 24 [0-30] 5a [0-30] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}