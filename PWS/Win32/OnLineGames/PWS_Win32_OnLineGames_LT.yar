
rule PWS_Win32_OnLineGames_LT{
	meta:
		description = "PWS:Win32/OnLineGames.LT,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 1c 03 00 00 54 c6 84 24 1d 03 00 00 4d c6 84 24 1e 03 00 00 32 } //1
		$a_01_1 = {c6 44 24 14 7a c6 44 24 16 69 c6 44 24 17 63 c6 44 24 19 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}