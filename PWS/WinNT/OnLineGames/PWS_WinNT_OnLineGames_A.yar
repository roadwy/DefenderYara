
rule PWS_WinNT_OnLineGames_A{
	meta:
		description = "PWS:WinNT/OnLineGames.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6b 6f 69 6f 69 79 74 67 68 68 39 39 2e 73 79 73 } //1 koioiytghh99.sys
		$a_00_1 = {ff 55 bc 33 db 8d 85 7c ff ff ff 53 53 68 60 09 00 00 6a 01 6a 01 53 53 50 } //1
		$a_02_2 = {39 5e 08 76 5e 53 e8 ?? ?? ff ff 8b 45 fc 8b 55 b8 8b c8 c1 e1 02 8b 84 0d 30 f2 ff ff 3b c2 76 37 8b 7d d4 03 fa 3b c7 73 2e 8b 3e 2b c2 53 8b 0c 39 8b f8 89 4d e8 e8 ?? ?? ff ff 03 7d f8 53 e8 58 fa ff ff 3b 7d e8 74 0e 53 e8 ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}