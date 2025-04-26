
rule PWS_Win32_OnLineGames_U{
	meta:
		description = "PWS:Win32/OnLineGames.U,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 ec 2d 36 38 38 c7 45 f0 44 42 35 46 c7 45 f4 41 35 42 45 c7 45 f8 42 7d 00 00 e8 bf 22 00 00 } //2
		$a_01_1 = {c7 45 d4 67 6f 6c 64 c7 45 d8 5f 63 6f 69 c7 45 dc 6e 00 00 00 89 75 e0 75 0f } //2
		$a_01_2 = {e8 dc 21 00 00 90 90 c7 45 d0 45 78 70 6c 89 5d d4 90 90 c7 45 e0 6f 72 65 72 89 5d e4 90 90 c7 45 f0 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}