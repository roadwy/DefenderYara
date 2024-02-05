
rule VirTool_Win32_Fcrypter_gen_B{
	meta:
		description = "VirTool:Win32/Fcrypter.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {59 83 74 0c 03 90 01 01 e2 f9 c3 90 09 10 00 68 90 01 04 68 90 01 04 54 68 90 01 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}