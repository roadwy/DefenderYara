
rule TrojanDownloader_BAT_Banload_AD{
	meta:
		description = "TrojanDownloader:BAT/Banload.AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 4c 6f 72 64 31 5c 47 58 5c 47 58 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 90 02 1f 2e 70 64 62 00 90 00 } //01 00 
		$a_01_1 = {24 31 30 38 32 66 39 66 36 2d 32 36 36 31 2d 34 65 63 65 2d 62 32 65 64 2d 65 61 61 36 34 32 34 33 35 64 35 65 00 } //01 00  ㄤ㠰昲昹ⴶ㘲ㄶ㐭捥ⵥ㉢摥攭慡㐶㐲㔳㕤e
		$a_01_2 = {75 00 69 00 78 00 70 00 71 00 6f 00 78 00 2e 00 7a 00 69 00 70 00 } //00 00  uixpqox.zip
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}