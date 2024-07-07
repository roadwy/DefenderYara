
rule HackTool_Win32_ZorKey_A_dha{
	meta:
		description = "HackTool:Win32/ZorKey.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_01_0 = {69 00 69 00 65 00 75 00 6e 00 68 00 35 00 32 00 33 00 58 00 73 00 61 00 77 00 } //100 iieunh523Xsaw
		$a_01_1 = {6b 00 30 00 33 00 20 00 } //100 k03 
		$a_01_2 = {7b 00 43 00 31 00 7d 00 00 00 00 00 7b 00 43 00 32 00 7d 00 00 00 00 00 7b 00 41 00 44 00 44 00 7d } //100
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=300
 
}