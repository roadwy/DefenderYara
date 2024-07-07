
rule VirTool_Win32_Obfuscator_WR{
	meta:
		description = "VirTool:Win32/Obfuscator.WR,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_13_0 = {e8 03 00 00 90 17 03 06 06 06 87 ff 87 ff 87 ff 8b d2 8b d2 8b d2 8a c0 8a c0 8a c0 90 00 0a } //10
		$a_8b_1 = {24 fc 51 b9 90 01 02 98 00 90 90 90 01 b0 90 02 46 49 0f } //8704
		$a_01_2 = {ff } //-28539
		$a_0c_3 = {24 } //-1 $
	condition:
		((#a_13_0  & 1)*10+(#a_8b_1  & 1)*8704+(#a_01_2  & 1)*-28539+(#a_0c_3  & 1)*-1) >=21
 
}