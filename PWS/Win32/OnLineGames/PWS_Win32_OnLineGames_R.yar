
rule PWS_Win32_OnLineGames_R{
	meta:
		description = "PWS:Win32/OnLineGames.R,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 18 69 e9 0a 05 00 00 0f af dd 03 f3 41 40 4a 75 ec } //1
		$a_00_1 = {2d 39 33 45 41 2d 34 34 41 32 2d 39 38 43 32 2d 43 30 36 39 42 37 44 30 43 41 36 37 7d 00 } //1 㤭䔳ⵁ㐴㉁㤭䌸ⴲぃ㤶㝂い䅃㜶}
		$a_00_2 = {36 32 41 42 33 37 42 43 00 } //1
		$a_00_3 = {67 6f 6c 64 5f 63 6f 69 6e } //1 gold_coin
		$a_00_4 = {73 69 6c 76 65 72 5f 63 6f 69 6e } //1 silver_coin
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}