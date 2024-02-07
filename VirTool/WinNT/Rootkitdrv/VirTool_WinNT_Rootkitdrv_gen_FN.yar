
rule VirTool_WinNT_Rootkitdrv_gen_FN{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FN,SIGNATURE_TYPE_PEHSTR,ffffffdf 00 6f 00 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 40 04 56 33 f6 3b c6 74 52 f6 40 06 05 74 05 8b 50 0c eb 10 } //64 00 
		$a_01_1 = {81 e9 84 c8 22 00 74 19 83 e9 04 74 10 81 e9 bc 03 00 00 0f 85 80 00 00 00 6a 33 eb 60 } //0a 00 
		$a_01_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 73 00 68 00 72 00 6f 00 75 00 64 00 33 00 32 00 } //0a 00  \Device\shroud32
		$a_01_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 73 00 68 00 72 00 6f 00 75 00 64 00 33 00 32 00 } //01 00  \DosDevices\shroud32
		$a_01_4 = {33 73 68 72 6f 75 64 2e 65 78 65 } //01 00  3shroud.exe
		$a_01_5 = {31 73 68 72 6f 75 64 33 32 2e 73 79 73 } //01 00  1shroud32.sys
		$a_01_6 = {35 73 68 72 6f 75 64 33 32 } //01 00  5shroud32
		$a_01_7 = {35 4c 45 47 41 43 59 5f 53 48 52 4f 55 44 33 32 } //00 00  5LEGACY_SHROUD32
	condition:
		any of ($a_*)
 
}