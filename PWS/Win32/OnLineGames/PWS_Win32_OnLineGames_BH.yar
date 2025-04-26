
rule PWS_Win32_OnLineGames_BH{
	meta:
		description = "PWS:Win32/OnLineGames.BH,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 70 6f 73 74 2e 61 73 70 00 } //1
		$a_01_1 = {26 61 63 63 6f 75 6e 74 3d 25 73 } //1 &account=%s
		$a_01_2 = {26 70 61 73 73 77 6f 72 64 } //1 &password
		$a_01_3 = {26 6c 65 76 65 6c } //1 &level
		$a_01_4 = {73 65 72 76 65 72 3d 25 73 } //1 server=%s
		$a_01_5 = {74 18 56 6a 32 6a 78 30 31 ff 75 08 } //5
		$a_01_6 = {80 3d d5 4f 55 00 85 0f 85 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=8
 
}