
rule PWS_Win32_OnLineGames_KO{
	meta:
		description = "PWS:Win32/OnLineGames.KO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0e 8a 06 d2 c0 32 c2 88 06 46 4b 85 db 75 ee } //1
		$a_03_1 = {68 5c fe ff ff 50 89 45 ?? ff d7 be 18 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}