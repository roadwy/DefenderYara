
rule VirTool_Win32_Dominicus_A{
	meta:
		description = "VirTool:Win32/Dominicus.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 69 6d 6f 73 43 32 2f 44 65 69 6d 6f 73 43 32 2f 61 67 65 6e 74 73 } //01 00  DeimosC2/DeimosC2/agents
		$a_01_1 = {44 65 69 6d 6f 73 43 32 2f 44 65 69 6d 6f 73 43 32 2f 6c 69 62 } //01 00  DeimosC2/DeimosC2/lib
		$a_01_2 = {68 74 74 70 2e 68 74 74 70 32 43 6c 69 65 6e 74 43 6f 6e 6e } //00 00  http.http2ClientConn
	condition:
		any of ($a_*)
 
}