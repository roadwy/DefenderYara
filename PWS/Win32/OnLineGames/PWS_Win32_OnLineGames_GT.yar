
rule PWS_Win32_OnLineGames_GT{
	meta:
		description = "PWS:Win32/OnLineGames.GT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 6d 62 3d 6b 69 63 6b } //1 &mb=kick
		$a_01_1 = {3d 3b 91 10 02 75 18 81 fb 00 00 7e 0e 75 10 83 ea 1c } //1
		$a_01_2 = {eb 08 eb 06 aa e9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}