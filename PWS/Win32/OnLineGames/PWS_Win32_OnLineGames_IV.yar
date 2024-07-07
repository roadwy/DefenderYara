
rule PWS_Win32_OnLineGames_IV{
	meta:
		description = "PWS:Win32/OnLineGames.IV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 6b 66 68 67 35 36 00 } //1 歷桦㕧6
		$a_01_1 = {5c c3 c0 c3 bc 2e 6a 70 67 2a } //1
		$a_03_2 = {5c ce d2 b5 c4 cf e0 c6 ac 90 02 01 2e 65 78 65 2a 90 00 } //1
		$a_01_3 = {b8 c3 c0 a6 b0 f3 c6 f7 bf c9 d2 d4 c0 a6 b0 f3 c8 ce ba ce d0 ce ca bd b5 c4 ce c4 bc fe a3 ac } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}