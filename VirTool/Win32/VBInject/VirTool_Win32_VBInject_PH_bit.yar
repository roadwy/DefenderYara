
rule VirTool_Win32_VBInject_PH_bit{
	meta:
		description = "VirTool:Win32/VBInject.PH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bd 18 00 00 00 [0-20] 64 8b 6d 00 [0-20] 8b 6d 30 [0-20] e9 } //1
		$a_03_1 = {85 c9 0f 85 [0-20] 41 [0-20] ff 77 2c [0-20] 31 0c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}