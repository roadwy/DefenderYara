
rule VirTool_WinNT_Rootkitdrv_LM{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 73 00 64 00 69 00 72 00 65 00 63 00 74 00 78 00 } //01 00  \Device\msdirectx
		$a_00_1 = {5c 4f 62 6a 65 63 74 54 79 70 65 73 5c 50 72 6f 63 65 73 73 } //01 00  \ObjectTypes\Process
		$a_03_2 = {81 7d fc f4 01 00 00 0f 8f 90 01 02 00 00 6a 00 8b 95 90 01 02 ff ff 03 55 90 01 01 52 8d 85 90 01 02 ff ff 50 e8 90 01 04 03 45 90 01 01 89 45 90 01 01 83 bd 90 01 02 ff ff 29 75 90 01 01 6a 00 8b 8d 90 01 02 ff ff 03 4d 90 01 01 51 8d 95 90 01 02 ff ff 52 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}