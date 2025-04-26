
rule VirTool_WinNT_Tedroo_gen_B{
	meta:
		description = "VirTool:WinNT/Tedroo.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fb 05 0f 85 b6 00 00 00 8b df 33 c0 89 45 fc 85 db 0f 84 a7 00 00 00 c6 45 fb 00 6a 01 8d 43 38 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}