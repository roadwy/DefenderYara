
rule Worm_Win32_Autorun_YZ{
	meta:
		description = "Worm:Win32/Autorun.YZ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {ff 75 94 e8 90 01 04 89 45 98 83 7d 98 02 0f 85 90 01 04 66 c7 45 bc 44 00 8d 45 ec e8 90 00 } //0a 00 
		$a_00_1 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //0a 00  GetLogicalDriveStringsA
		$a_00_2 = {5b 41 75 74 6f 52 75 6e 5d 0a 73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //01 00 
		$a_00_3 = {5c 64 65 66 61 75 6c 74 2e 69 6e 66 } //01 00  \default.inf
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 00 48 69 64 64 65 6e } //00 00  潓瑦慷敲䵜捩潲潳瑦坜湩潤獷䍜牵敲瑮敖獲潩屮硅汰牯牥䅜癤湡散d楈摤湥
	condition:
		any of ($a_*)
 
}