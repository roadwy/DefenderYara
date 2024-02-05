
rule VirTool_WinNT_Rootkitdrv_KY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 ff 00 8b 45 24 83 20 00 8b 45 24 83 60 04 00 8b 45 20 89 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 81 6d 90 01 01 04 00 61 25 90 00 } //01 00 
		$a_03_1 = {3b 45 1c 75 09 c7 45 90 01 01 06 00 00 80 eb 06 8b 45 90 01 01 83 20 00 8d 45 90 01 01 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}