
rule PWS_Win32_OnLineGames_GS{
	meta:
		description = "PWS:Win32/OnLineGames.GS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 42 74 72 6c 00 } //1
		$a_01_1 = {81 fb 41 50 33 32 75 3d 8b 5e 04 83 fb 18 72 35 } //1
		$a_01_2 = {6a 40 52 ff d5 8b 84 24 9c 00 00 00 6a 00 50 57 ff d3 57 6a 01 8d 8c 24 b4 00 00 00 68 f8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}