
rule VirTool_WinNT_Rootkitdrv_AW{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AW,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 79 00 73 00 44 00 72 00 76 00 65 00 72 00 } //10 \Device\SysDrver
		$a_00_1 = {5c 6f 62 6a 66 72 65 5f 77 6e 65 74 5f 78 38 36 5c 69 33 38 36 5c 53 79 73 44 72 76 65 72 2e 70 64 62 } //10 \objfre_wnet_x86\i386\SysDrver.pdb
		$a_00_2 = {89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
		$a_02_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 83 3d ?? ?? ?? 00 00 8b 0d } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=22
 
}