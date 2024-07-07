
rule Worm_Win32_Hokobot_B_dha{
	meta:
		description = "Worm:Win32/Hokobot.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {58 58 58 54 6f 6d 61 74 6f 3d } //1 XXXTomato=
		$a_00_1 = {76 69 6d 2e 64 61 74 00 } //1
		$a_00_2 = {2f 77 69 70 2f 69 6e 64 65 78 2e 70 68 70 00 } //1
		$a_00_3 = {65 00 72 00 72 00 6f 00 72 00 2e 00 72 00 65 00 6e 00 61 00 6d 00 65 00 66 00 69 00 6c 00 65 00 00 00 } //1
		$a_01_4 = {5b 61 75 74 6f 72 75 6e 5d } //5 [autorun]
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*5) >=8
 
}