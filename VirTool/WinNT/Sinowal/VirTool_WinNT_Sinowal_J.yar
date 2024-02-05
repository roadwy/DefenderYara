
rule VirTool_WinNT_Sinowal_J{
	meta:
		description = "VirTool:WinNT/Sinowal.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 75 10 ff 75 0c ff 55 fc } //01 00 
		$a_01_1 = {8b 45 08 05 cc 01 00 00 50 } //01 00 
		$a_03_2 = {83 7d 08 00 75 07 32 c0 e9 90 01 04 8b 45 f0 0f b7 00 3d 4d 5a 00 00 74 07 32 c0 e9 90 01 04 8b 45 f0 8b 4d 08 03 48 3c 89 4d ec 8b 45 ec 81 38 50 45 00 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}