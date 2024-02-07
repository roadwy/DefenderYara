
rule VirTool_WinNT_Dogrobot_gen_M{
	meta:
		description = "VirTool:WinNT/Dogrobot.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {3d 00 00 00 80 72 90 01 01 80 38 83 75 90 01 01 8b c0 80 78 01 4d 75 90 00 } //0a 00 
		$a_02_1 = {25 ff ff fe ff 0f 22 c0 81 3d 90 01 08 0f 84 90 00 } //0a 00 
		$a_00_2 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 53 00 61 00 66 00 65 00 44 00 6f 00 67 00 } //0a 00  \Driver\SafeDog
		$a_00_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 30 00 } //0a 00  \Device\Harddisk0
		$a_00_4 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 43 00 } //00 00  \Driver\ProtectedC
	condition:
		any of ($a_*)
 
}