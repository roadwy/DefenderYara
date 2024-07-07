
rule VirTool_WinNT_Rootkitdrv_gen_FH{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FH,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b ce c1 e9 02 b8 90 90 90 90 8b fa f3 ab 8b ce 8b 75 08 83 e1 03 f3 aa } //1
		$a_01_1 = {8d 88 04 02 00 00 8b 11 3b d3 74 0c 8b b0 08 02 00 00 89 b2 08 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}