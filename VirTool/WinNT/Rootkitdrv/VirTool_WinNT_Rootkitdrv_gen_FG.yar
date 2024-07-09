
rule VirTool_WinNT_Rootkitdrv_gen_FG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c7 45 c8 00 04 00 00 c7 45 cc 00 00 00 00 c7 45 d0 00 02 00 00 c7 45 d4 00 01 00 00 c7 45 d8 01 01 00 00 b9 05 00 00 00 } //1
		$a_02_1 = {8b 45 08 50 ff 15 ?? ?? ?? ?? 89 45 f8 81 7d 1c 03 00 12 00 74 08 8b 45 f8 e9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}