
rule VirTool_Win64_Casinj_A{
	meta:
		description = "VirTool:Win64/Casinj.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 38 33 c0 45 33 c9 48 21 44 24 20 48 ba 88 88 88 88 88 88 88 88 ?? 99 99 99 99 99 99 99 99 49 b8 77 77 77 77 77 77 77 77 ?? ?? ?? ?? 48 b8 66 66 66 66 66 66 66 66 ff d0 33 c0 48 83 c4 38 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}