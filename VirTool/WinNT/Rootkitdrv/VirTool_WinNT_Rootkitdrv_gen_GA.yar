
rule VirTool_WinNT_Rootkitdrv_gen_GA{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!GA,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {57 33 ff 89 3d 90 01 04 89 3d 90 01 04 89 3d 90 01 04 89 3d 90 01 04 8b 4e 01 8b 10 8b 0c 8a 89 0d 90 01 04 8b 48 08 c1 e1 02 90 00 } //10
		$a_02_1 = {8b 56 01 b9 90 01 04 8d 04 90 90 87 08 89 0d 90 01 04 33 c0 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}