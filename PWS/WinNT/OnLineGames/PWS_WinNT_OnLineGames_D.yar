
rule PWS_WinNT_OnLineGames_D{
	meta:
		description = "PWS:WinNT/OnLineGames.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 06 80 f1 90 01 01 88 08 40 4f 75 f4 90 00 } //01 00 
		$a_03_1 = {8d 34 70 81 fe 02 00 00 01 0f 90 01 02 01 00 00 90 00 } //01 00 
		$a_03_2 = {f3 a6 74 18 bf 90 01 04 8d b5 90 01 04 6a 90 01 01 59 33 c0 f3 a6 0f 90 00 } //01 00 
		$a_03_3 = {b9 00 80 00 00 33 c0 68 90 01 02 01 00 f3 ab ff 35 90 01 04 68 90 01 02 01 00 e8 90 01 02 ff ff 85 c0 74 90 00 } //01 00 
		$a_01_4 = {66 81 38 64 a1 75 27 66 81 78 06 8a 80 75 1f 0f b7 48 02 } //00 00 
	condition:
		any of ($a_*)
 
}