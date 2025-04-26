
rule PWS_Win32_OnLineGames_DNF{
	meta:
		description = "PWS:Win32/OnLineGames.DNF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 65 50 56 c6 45 ?? 55 c6 45 fd 56 c6 45 fe 42 88 5d ff e8 } //1
		$a_03_1 = {6a 05 ff 15 ?? ?? 40 00 56 6a 00 43 ff d7 85 c0 75 07 83 fb 0a 7c e9 eb 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}