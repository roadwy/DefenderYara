
rule VirTool_Win32_CeeInject_MK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d a0 03 4d e4 8b 55 f0 03 55 bc 66 8b 01 66 89 02 8a 49 02 88 4a 02 } //01 00 
		$a_03_1 = {8b 45 08 03 45 fc 0f b6 08 8b 15 90 01 04 81 c2 90 01 04 33 ca 8b 45 08 03 45 fc 88 08 eb 90 00 } //01 00 
		$a_03_2 = {7d 1b 8b 55 90 01 01 03 55 90 01 01 0f b6 02 8b 4d 90 01 01 6b c9 90 01 01 33 c1 8b 55 90 01 01 03 55 90 01 01 88 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_MK_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 00 3d 00 77 00 56 00 6c 00 78 00 47 00 5a 00 75 00 46 00 47 00 53 00 6c 00 78 00 57 00 64 00 6b 00 39 00 57 00 54 00 30 00 56 00 32 00 52 00 } //01 00  ==wVlxGZuFGSlxWdk9WT0V2R
		$a_01_1 = {3d 00 3d 00 51 00 65 00 79 00 39 00 57 00 62 00 6c 00 31 00 55 00 5a 00 32 00 39 00 57 00 54 00 73 00 52 00 6e 00 55 00 } //01 00  ==Qey9Wbl1UZ29WTsRnU
		$a_01_2 = {3d 00 3d 00 77 00 56 00 6c 00 52 00 58 00 64 00 6a 00 56 00 47 00 65 00 46 00 78 00 47 00 62 00 6c 00 68 00 32 00 55 00 } //01 00  ==wVlRXdjVGeFxGblh2U
		$a_01_3 = {6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 } //01 00  nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_01_4 = {73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 54 00 4e 00 20 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 } //00 00  swodniW\noisreVtnerruC\TN swodniW\tfosorciM\erawtfoS
	condition:
		any of ($a_*)
 
}