
rule VirTool_WinNT_Fispids_gen_B{
	meta:
		description = "VirTool:WinNT/Fispids.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 dc e9 2b cf 83 e9 05 89 4d dd 6a 05 57 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}