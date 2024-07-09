
rule PWS_Win32_Reveton_B{
	meta:
		description = "PWS:Win32/Reveton.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 80 e4 2a 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 ba bb 01 e8 } //1
		$a_03_1 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 90 09 03 00 c7 } //1
		$a_01_2 = {50 6f 6b 65 72 53 74 61 72 73 5c 75 73 65 72 2e 69 6e 69 } //1 PokerStars\user.ini
		$a_01_3 = {54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 } //1 TurboFTP\addrbk.dat
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}