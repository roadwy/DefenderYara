
rule VirTool_WinNT_Rootkitdrv_OG_bit{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.OG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 52 65 31 39 38 36 53 44 54 44 4f 53 } //1 \\.\Re1986SDTDOS
		$a_01_1 = {5c 4e 65 74 42 6f 74 5c 69 33 38 36 5c 52 65 53 53 44 54 2e 70 64 62 } //1 \NetBot\i386\ReSSDT.pdb
		$a_01_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}