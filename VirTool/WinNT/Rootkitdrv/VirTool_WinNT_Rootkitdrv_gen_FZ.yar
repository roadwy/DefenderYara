
rule VirTool_WinNT_Rootkitdrv_gen_FZ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FZ,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {eb 1e 83 3d ?? ?? ?? ?? 00 75 13 8b 4d f8 51 e8 4d 00 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 eb } //10
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 77 00 72 00 61 00 70 00 70 00 65 00 72 00 36 00 34 00 78 00 } //1 \Device\wrapper64x
		$a_00_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 77 00 72 00 61 00 70 00 70 00 65 00 72 00 36 00 34 00 78 00 } //1 \DosDevices\wrapper64x
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}