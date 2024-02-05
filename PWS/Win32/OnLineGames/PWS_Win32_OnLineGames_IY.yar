
rule PWS_Win32_OnLineGames_IY{
	meta:
		description = "PWS:Win32/OnLineGames.IY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2c 21 01 00 a1 90 01 04 3b c3 56 8b 35 90 01 04 74 09 50 ff d6 89 1d 90 00 } //01 00 
		$a_01_1 = {44 61 72 6b 53 74 6f 72 79 4f 6e 6c 69 6e 65 } //01 00 
		$a_01_2 = {40 47 61 6d 65 48 6f 6f 6b 2e 44 4c 4c } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 78 75 61 6e 62 62 73 2e 6e 65 74 2f 62 62 73 } //00 00 
	condition:
		any of ($a_*)
 
}