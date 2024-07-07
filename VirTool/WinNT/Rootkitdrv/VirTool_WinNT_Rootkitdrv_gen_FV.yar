
rule VirTool_WinNT_Rootkitdrv_gen_FV{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FV,SIGNATURE_TYPE_PEHSTR_EXT,16 00 0b 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 7d c0 00 74 90 01 01 8b 45 e4 8b 10 a1 90 01 01 05 01 00 3b 50 08 73 90 01 01 8b 08 fa 90 00 } //10
		$a_00_1 = {85 ff 75 08 8b 45 d4 89 46 1c eb 04 } //10
		$a_00_2 = {43 00 65 00 5c 00 44 00 61 00 72 00 6b 00 53 00 68 00 65 00 6c 00 6c 00 } //1 Ce\DarkShell
		$a_00_3 = {5c 00 3f 00 3f 00 5c 00 44 00 61 00 72 00 6b 00 32 00 31 00 31 00 38 00 } //1 \??\Dark2118
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}