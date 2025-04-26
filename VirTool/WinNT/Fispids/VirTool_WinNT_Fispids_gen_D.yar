
rule VirTool_WinNT_Fispids_gen_D{
	meta:
		description = "VirTool:WinNT/Fispids.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 45 dc e9 2b (c1|ca) 83 90 03 01 01 e8 e9 05 89 90 03 01 01 45 4d dd 6a 05 90 03 01 01 51 52 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}