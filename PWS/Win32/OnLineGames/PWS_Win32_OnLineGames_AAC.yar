
rule PWS_Win32_OnLineGames_AAC{
	meta:
		description = "PWS:Win32/OnLineGames.AAC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 83 c0 05 89 45 f4 8b 4d 08 c1 e1 08 81 c1 90 01 04 2b 4d f4 89 4d f4 8b 55 0c 03 55 fc c6 02 e9 8b 45 fc 90 00 } //2
		$a_02_1 = {83 c4 14 68 90 01 04 6a 05 8d 8d 90 01 02 ff ff 51 8b 55 90 01 01 52 6a 90 01 01 e8 90 00 } //2
		$a_00_2 = {33 36 30 53 45 } //1 360SE
		$a_00_3 = {54 54 72 61 76 65 6c 65 72 } //1 TTraveler
		$a_00_4 = {54 68 65 57 6f 72 6c 64 } //1 TheWorld
		$a_00_5 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 } //1 elementclient
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}