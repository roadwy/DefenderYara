
rule VirTool_WinNT_Rootkitdrv_GP{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 65 fc 00 6a 04 6a 04 53 ff 15 90 01 04 6a 04 6a 04 57 ff 15 90 01 04 83 4d fc ff 90 00 } //01 00 
		$a_01_1 = {8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 65 e4 00 eb } //00 00 
	condition:
		any of ($a_*)
 
}