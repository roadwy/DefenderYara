
rule VirTool_WinNT_Rootkitdrv_gen_FD{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FD,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 80 38 b8 74 04 32 c0 eb 0b 8b 40 01 8b 4c 24 0c 89 01 b0 01 } //1
		$a_01_1 = {e8 83 ff ff ff 8b 45 e4 8b 4d 08 89 48 04 8b 02 8b 4d e4 89 41 08 8b 45 0c 89 02 8b 45 e4 c6 00 01 8b 4d e4 e8 53 ff ff ff b0 01 88 45 df eb 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}