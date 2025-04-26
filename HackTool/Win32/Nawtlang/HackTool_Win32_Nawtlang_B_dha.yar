
rule HackTool_Win32_Nawtlang_B_dha{
	meta:
		description = "HackTool:Win32/Nawtlang.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 00 32 00 2e 00 39 00 30 00 2e 00 31 00 34 00 34 00 2e 00 34 00 30 00 } //10 52.90.144.40
	condition:
		((#a_00_0  & 1)*10) >=10
 
}