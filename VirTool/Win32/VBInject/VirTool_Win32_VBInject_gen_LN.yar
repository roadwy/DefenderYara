
rule VirTool_Win32_VBInject_gen_LN{
	meta:
		description = "VirTool:Win32/VBInject.gen!LN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_13_0 = {0f 6e 45 00 90 02 20 66 0f 6e cc 90 02 30 66 0f ef c1 90 02 30 66 0f 7e 45 fc 90 02 20 81 7d fc 90 90 90 90 90 90 90 90 75 90 00 01 } //1
		$a_0f_1 = {6e 4c 24 08 90 02 20 0f ef c1 90 02 20 0f 7e 45 00 83 c5 } //8192
		$a_20_2 = {7c 24 } //-28668 |$
	condition:
		((#a_13_0  & 1)*1+(#a_0f_1  & 1)*8192+(#a_20_2  & 1)*-28668) >=3
 
}