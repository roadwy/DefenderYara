
rule VirTool_Win32_BopToolz_B_MTB{
	meta:
		description = "VirTool:Win32/BopToolz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 08 6a 04 68 10 90 01 03 6a 04 6a 00 68 40 90 01 03 ff 75 f8 ff 90 00 } //01 00 
		$a_02_1 = {50 68 19 00 02 00 6a 0c 68 a0 90 01 03 ff 75 f4 ff 90 00 } //01 00 
		$a_02_2 = {6a 04 68 10 90 01 03 6a 04 6a 00 68 40 90 01 03 ff 75 f8 ff 90 00 } //01 00 
		$a_02_3 = {83 c4 08 a3 10 90 01 03 8d 45 90 01 01 50 68 02 00 00 80 ff 35 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}