
rule VirTool_WinNT_Livuto_gen_A{
	meta:
		description = "VirTool:WinNT/Livuto.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 65 da 00 c6 45 d4 ea c6 45 d9 08 c6 45 db 90 c6 45 dc 90 c6 45 dd 90 89 4d d5 fa } //01 00 
		$a_01_1 = {c6 45 e4 55 c6 45 e5 8b c6 45 e6 ec c6 45 e7 6a c6 45 e9 68 c6 45 ea aa c6 45 eb aa } //02 00 
		$a_01_2 = {61 00 62 00 6f 00 75 00 74 00 2e 00 62 00 6c 00 61 00 6e 00 6b 00 2e 00 6c 00 61 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}