
rule PWS_Win32_OnLineGames_IS{
	meta:
		description = "PWS:Win32/OnLineGames.IS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3f 61 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 } //1 ?a=postmb&u=%s&mb=%
		$a_03_1 = {3f 73 3d 25 73 26 61 3d 25 73 26 ?? 3d 25 73 } //1
		$a_01_2 = {83 c4 f4 83 c4 0c 50 58 5d 33 db 89 5d e4 c6 45 dc 57 c6 45 dd 69 c6 45 de 6e c6 45 df 49 c6 45 e0 6e c6 45 e1 65 c6 45 e2 74 88 5d e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}