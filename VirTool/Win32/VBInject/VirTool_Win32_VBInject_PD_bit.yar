
rule VirTool_Win32_VBInject_PD_bit{
	meta:
		description = "VirTool:Win32/VBInject.PD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 18 00 00 00 [0-30] 64 8b 1b [0-30] 8b 5b 30 [0-30] e9 ?? ?? 00 00 58 [0-30] 02 43 02 [0-30] ff e0 } //1
		$a_03_1 = {81 79 04 56 00 42 00 75 [0-30] 81 39 4d 00 53 00 75 } //1
		$a_03_2 = {83 fa 00 75 [0-40] 6a 78 [0-40] 58 [0-40] 31 d2 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 33 14 03 } //1
		$a_03_3 = {85 c9 0f 85 [0-40] 8b 53 2c [0-30] 31 ca [0-60] 6a 78 [0-30] 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}