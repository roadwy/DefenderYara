
rule VirTool_WinNT_Rootkitdrv_gen_FC{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FC,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d f8 3b 08 73 39 8b 55 f8 8b 45 08 83 7c 90 04 00 74 2a 8b 4d f8 8b 55 fc 8b 45 f8 8b 75 08 8b 0c 8a 3b 4c 86 04 74 15 8b 55 f8 8b 45 08 8b 4c 90 04 8b 55 f8 8b 45 fc 8d 14 90 87 0a } //01 00 
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 66 00 73 00 6f 00 64 00 68 00 66 00 6e 00 32 00 6d 00 } //01 00 
		$a_01_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 66 00 73 00 6f 00 64 00 68 00 66 00 6e 00 32 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}