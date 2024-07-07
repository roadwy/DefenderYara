
rule VirTool_WinNT_Rootkitdrv_gen_FE{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FE,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 01 0c 00 00 bb 00 60 01 00 05 fd d4 5a 6e 31 03 83 eb fc 49 21 c9 75 f1 61 8d 64 24 fc c7 04 24 00 60 01 00 83 c4 04 ff 64 24 fc } //1
		$a_01_1 = {35 98 96 95 29 d3 c0 05 f6 20 89 95 83 c1 ff 83 f9 00 75 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}