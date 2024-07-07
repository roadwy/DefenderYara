
rule VirTool_WinNT_KillProc_A{
	meta:
		description = "VirTool:WinNT/KillProc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 4b 00 49 00 4c 00 4c 00 50 00 53 00 5f 00 44 00 72 00 76 00 00 00 } //1
		$a_03_1 = {81 7c 24 24 04 20 22 00 75 90 14 83 65 1c 00 90 00 } //1
		$a_03_2 = {ff 45 f0 8b 45 fc 8b 4d f0 01 7d ec 01 7d f4 3b 08 72 90 01 01 eb 90 01 01 8b 45 ec 8b 40 08 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}