
rule PWS_Win32_OnLineGames_LI{
	meta:
		description = "PWS:Win32/OnLineGames.LI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 58 79 25 64 6e 64 2e 74 65 6d 70 } //1 %s\Xy%dnd.temp
		$a_00_1 = {42 45 47 49 4e 20 46 55 57 55 } //1 BEGIN FUWU
		$a_00_2 = {b2 e9 d5 d2 50 45 49 5a 49 d0 c5 cf a2 } //1
		$a_00_3 = {4a 49 4a 49 20 20 53 48 41 4e 47 58 49 41 4e } //1 JIJI  SHANGXIAN
		$a_03_4 = {8b 48 34 03 48 28 eb 08 8b 4d 90 01 01 8b 49 28 03 c8 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}