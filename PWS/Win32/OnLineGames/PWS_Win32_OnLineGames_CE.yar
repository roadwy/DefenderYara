
rule PWS_Win32_OnLineGames_CE{
	meta:
		description = "PWS:Win32/OnLineGames.CE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b ca 8a d1 02 d0 30 10 40 8d 14 01 81 fa 00 01 00 00 72 ee } //1
		$a_01_1 = {2b f7 89 47 06 83 ee 0a c6 47 0a e9 89 77 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}