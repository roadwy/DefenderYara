
rule PWS_Win32_OnLineGames_LA{
	meta:
		description = "PWS:Win32/OnLineGames.LA,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //0a 00 
		$a_01_1 = {73 66 63 5f 6f 73 2e 64 6c 6c } //01 00 
		$a_01_2 = {c6 45 cc 6f c6 45 cd 6c c6 45 ce 68 c6 45 cf 65 } //01 00 
		$a_01_3 = {c6 45 dd 65 c6 45 de 74 c6 45 df 54 c6 45 e0 65 } //00 00 
	condition:
		any of ($a_*)
 
}