
rule VirTool_WinNT_Hackdef_gen_B{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!B,SIGNATURE_TYPE_PEHSTR,7d 00 7d 00 0b 00 00 16 00 "
		
	strings :
		$a_01_0 = {89 55 fc 89 4f 1c c7 45 b8 18 00 00 00 89 5d bc 89 5d c0 89 5d c4 89 5d c8 89 5d cc 89 5d ec } //16 00 
		$a_01_1 = {8b 45 fc 89 45 e8 8d 45 e8 50 8d 45 b8 50 68 ff 0f 1f 00 8d 45 f0 50 89 5d ec } //03 00 
		$a_01_2 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 } //16 00  ZwOpenProcess
		$a_01_3 = {85 c0 7c 6c 8d 45 0c 50 68 ff 00 0f 00 ff 75 f0 } //03 00 
		$a_01_4 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //16 00  ZwOpenProcessToken
		$a_01_5 = {7c 4d 8d 45 d0 50 6a 01 53 8d 45 b8 50 68 ff 00 0f 00 ff 75 0c } //03 00 
		$a_01_6 = {5a 77 44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e } //16 00  ZwDuplicateToken
		$a_01_7 = {85 c0 7c 27 6a 08 8d 45 d0 50 6a 09 ff 75 dc 89 5d d4 } //03 00 
		$a_01_8 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //16 00  ZwSetInformationProcess
		$a_01_9 = {8b 0e 8d 46 04 89 45 fc 8b 00 89 45 d8 8d 45 f8 50 89 1e 51 c7 47 1c 04 } //03 00 
		$a_01_10 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 44 } //00 00  PsLookupProcessByProcessID
	condition:
		any of ($a_*)
 
}