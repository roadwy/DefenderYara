
rule VirTool_WinNT_Rootkitdrv_LS{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_03_1 = {ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 02 01 00 89 45 90 01 01 85 c0 0f 8c 90 01 02 00 00 83 7d 24 03 0f 85 90 01 02 00 00 c7 45 90 01 03 01 00 89 5d 90 01 01 83 65 90 01 01 00 33 c0 39 03 0f 94 c0 90 00 } //01 00 
		$a_03_2 = {6a 03 59 8b bd 90 01 02 ff ff 8b 95 90 01 02 ff ff 8b f2 33 c0 f3 a6 0f 84 90 01 02 00 00 8a 02 3c e9 74 08 3c cc 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}