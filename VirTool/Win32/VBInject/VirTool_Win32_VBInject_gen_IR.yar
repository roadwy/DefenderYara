
rule VirTool_Win32_VBInject_gen_IR{
	meta:
		description = "VirTool:Win32/VBInject.gen!IR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {37 00 37 00 7c 00 39 00 30 00 7c 00 31 00 32 00 38 00 7c 00 30 00 7c 00 31 00 7c 00 30 00 7c 00 30 00 7c 00 30 00 7c 00 } //1 77|90|128|0|1|0|0|0|
		$a_03_1 = {0f bf c0 33 45 90 01 01 50 e8 90 01 04 8b d0 8d 4d 90 01 01 e8 90 01 04 50 e8 90 01 04 8b d0 8d 4d 90 01 01 e8 90 01 04 8d 45 90 01 01 50 8d 45 90 01 01 50 6a 02 e8 90 01 04 83 c4 0c 8d 45 90 01 01 50 8d 45 90 01 01 50 6a 02 e8 90 01 04 83 c4 0c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}