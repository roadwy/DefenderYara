
rule VirTool_WinNT_Rootkitdrv_LA{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 87 90 01 04 33 c9 8a 0d 90 01 04 33 c1 8b 4d 90 01 01 88 04 0f 47 eb 90 00 } //01 00 
		$a_03_1 = {53 8a 1c 11 32 1d 90 01 04 88 1a 42 48 75 f1 5b 90 00 } //01 00 
		$a_03_2 = {6a 08 8d 45 90 01 01 50 6a 09 6a ff ff 15 90 01 04 f6 45 08 02 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}