
rule HackTool_Win32_ZorCook_A_dha{
	meta:
		description = "HackTool:Win32/ZorCook.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_01_0 = {69 00 69 00 65 00 75 00 6e 00 68 00 35 00 32 00 33 00 58 00 73 00 61 00 77 00 } //100 iieunh523Xsaw
		$a_01_1 = {53 00 6f 00 6d 00 65 00 74 00 68 00 69 00 6e 00 67 00 20 00 67 00 6f 00 6e 00 65 00 20 00 77 00 72 00 6f 00 6e 00 67 00 2e 00 20 00 43 00 68 00 } //100 Something gone wrong. Ch
		$a_01_2 = {43 00 68 00 2e 00 73 00 6c 00 74 00 65 00 } //100 Ch.slte
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=300
 
}