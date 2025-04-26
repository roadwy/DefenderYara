
rule VirTool_WinNT_Cutwail_gen_C{
	meta:
		description = "VirTool:WinNT/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7d e0 00 24 6c 9d 74 02 eb 16 } //1
		$a_01_1 = {81 3a 52 43 50 54 75 02 eb 02 eb dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}