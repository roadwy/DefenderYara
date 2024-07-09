
rule VirTool_WinNT_Rootkitdrv_gen_FP{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FP,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 76 83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 57 ff 15 } //10
		$a_00_1 = {8b 45 ec 8b 00 8b 00 89 45 c0 6a 01 58 c3 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}