
rule PWS_Win32_OnLineGames_ZDK{
	meta:
		description = "PWS:Win32/OnLineGames.ZDK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 20 67 6f 00 65 78 69 73 74 20 22 00 69 66 20 00 22 00 } //1
		$a_03_1 = {53 61 66 00 90 01 0c 36 30 00 00 33 00 00 00 90 00 } //1
		$a_03_2 = {74 21 50 6a 00 68 01 04 10 00 ff 15 90 01 03 00 8b f0 6a 01 56 ff d5 6a 00 56 ff d5 56 ff 15 90 01 03 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}