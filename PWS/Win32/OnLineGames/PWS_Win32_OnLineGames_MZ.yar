
rule PWS_Win32_OnLineGames_MZ{
	meta:
		description = "PWS:Win32/OnLineGames.MZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 70 3d 25 73 26 75 70 3d 25 73 26 70 70 3d 25 73 26 73 73 70 3d 25 73 } //1 %s?ap=%s&up=%s&pp=%s&ssp=%s
		$a_01_1 = {25 73 3f 75 70 3d 25 73 26 70 70 3d 25 73 26 73 73 70 3d 25 73 } //1 %s?up=%s&pp=%s&ssp=%s
		$a_03_2 = {3d 11 22 33 44 bd 01 00 00 00 0f 85 ?? ?? ?? ?? b9 2c 0b 00 00 } //2
		$a_01_3 = {66 3d 06 00 74 0b 66 3d 05 00 74 05 bd 02 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}