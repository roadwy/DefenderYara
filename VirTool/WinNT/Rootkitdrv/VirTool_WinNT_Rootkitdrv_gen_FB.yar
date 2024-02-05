
rule VirTool_WinNT_Rootkitdrv_gen_FB{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 c0 01 00 00 00 83 65 fc 00 6a 04 6a 04 52 ff 15 3c 05 01 00 6a 04 6a 04 56 ff 15 38 05 01 00 83 4d fc ff eb 22 } //01 00 
		$a_01_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 b9 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 ff eb 05 } //00 00 
	condition:
		any of ($a_*)
 
}