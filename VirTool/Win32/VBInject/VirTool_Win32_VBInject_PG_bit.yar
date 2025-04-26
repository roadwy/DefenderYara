
rule VirTool_Win32_VBInject_PG_bit{
	meta:
		description = "VirTool:Win32/VBInject.PG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {bd 18 00 00 00 [0-20] 64 8b 6d 00 [0-20] 8b 6d 30 [0-20] e9 } //1
		$a_03_1 = {58 02 45 02 [0-20] ff e0 } //1
		$a_03_2 = {85 c9 0f 85 [0-20] 41 [0-20] 8b 57 2c [0-20] 31 ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}