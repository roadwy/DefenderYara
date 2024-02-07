
rule PWS_Win32_OnLineGames_AAB{
	meta:
		description = "PWS:Win32/OnLineGames.AAB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 5a 52 ff 25 } //02 00 
		$a_01_1 = {8b 4c 24 44 8b 01 35 55 8b ec 83 } //01 00 
		$a_01_2 = {4b 56 4d 6f 6e 58 50 } //01 00  KVMonXP
		$a_01_3 = {48 6f 6f 6b 6f 66 66 } //01 00  Hookoff
		$a_01_4 = {36 30 73 61 66 65 } //00 00  60safe
	condition:
		any of ($a_*)
 
}