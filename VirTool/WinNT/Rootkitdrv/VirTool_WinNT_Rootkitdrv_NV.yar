
rule VirTool_WinNT_Rootkitdrv_NV{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.NV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {cc 6c 73 30 73 73 2e 65 78 65 90 09 1d 00 81 ?? ?? 90 90 90 90 90 90 90 90 74 ?? ?? 3d 78 09 00 00 7c } //1
		$a_00_1 = {68 72 79 41 00 68 65 63 74 6f 68 6d 44 69 72 68 79 73 74 65 68 47 65 74 53 e8 } //1
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 00 00 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}