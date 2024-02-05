
rule VirTool_WinNT_Nedsym_gen_A{
	meta:
		description = "VirTool:WinNT/Nedsym.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 06 59 8d 45 e0 50 be f6 04 01 00 8d 7d e0 f3 a5 33 f6 8d 45 f8 50 89 35 88 06 01 00 } //01 00 
		$a_01_1 = {48 69 64 65 50 6f 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}