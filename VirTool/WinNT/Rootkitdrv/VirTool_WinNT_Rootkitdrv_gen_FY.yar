
rule VirTool_WinNT_Rootkitdrv_gen_FY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FY,SIGNATURE_TYPE_PEHSTR,1e 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {85 f6 75 08 8b 4d d4 89 4b 1c eb } //10
		$a_01_1 = {8b 65 e8 8b 75 c0 c7 45 fc ff ff ff ff 8b 5d 0c } //10
		$a_01_2 = {8b 4d ec 8b 11 8b 02 89 45 c0 b8 01 00 00 00 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}