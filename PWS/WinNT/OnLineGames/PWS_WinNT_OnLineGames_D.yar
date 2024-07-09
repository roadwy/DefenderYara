
rule PWS_WinNT_OnLineGames_D{
	meta:
		description = "PWS:WinNT/OnLineGames.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 06 80 f1 ?? 88 08 40 4f 75 f4 } //1
		$a_03_1 = {8d 34 70 81 fe 02 00 00 01 0f ?? ?? 01 00 00 } //1
		$a_03_2 = {f3 a6 74 18 bf ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 6a ?? 59 33 c0 f3 a6 0f } //1
		$a_03_3 = {b9 00 80 00 00 33 c0 68 ?? ?? 01 00 f3 ab ff 35 ?? ?? ?? ?? 68 ?? ?? 01 00 e8 ?? ?? ff ff 85 c0 74 } //1
		$a_01_4 = {66 81 38 64 a1 75 27 66 81 78 06 8a 80 75 1f 0f b7 48 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}