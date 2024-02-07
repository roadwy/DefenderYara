
rule HackTool_Win32_Nawtlang_A_dha{
	meta:
		description = "HackTool:Win32/Nawtlang.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4b 00 68 00 61 00 72 00 70 00 65 00 64 00 61 00 72 00 31 00 32 00 33 00 21 00 } //00 00  Kharpedar123!
	condition:
		any of ($a_*)
 
}