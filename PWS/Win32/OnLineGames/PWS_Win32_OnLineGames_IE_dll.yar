
rule PWS_Win32_OnLineGames_IE_dll{
	meta:
		description = "PWS:Win32/OnLineGames.IE!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 2f 25 2a 64 2e 25 2a 64 20 25 64 } //1 HTTP/%*d.%*d %d
		$a_01_1 = {b5 d8 cf c2 b3 c7 } //1
		$a_01_2 = {25 64 00 00 4c 76 2e 25 64 00 00 00 bd f0 b1 d2 } //1
		$a_01_3 = {26 6c 6f 6f 6b 3d 00 00 26 67 6f 6c 64 3d 00 00 26 6c 6f 63 6b 3d 00 00 26 72 6f 6c 65 3d 00 00 26 6e 61 6d 65 3d } //1
		$a_01_4 = {26 78 78 78 78 3d 00 00 26 75 73 65 72 3d 00 00 26 6c 69 6e 65 3d 00 00 26 73 69 67 6e 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}