
rule PWS_Win32_OnLineGames_XZA{
	meta:
		description = "PWS:Win32/OnLineGames.XZA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 6a 40 6a 02 56 ff 15 84 80 00 10 } //01 00 
		$a_02_1 = {ff ff ff 61 ff 25 90 09 07 00 60 ff 90 01 03 e8 90 00 } //01 00 
		$a_02_2 = {00 4b 73 55 73 65 72 2e 64 6c 6c 90 01 30 90 02 04 6c 70 6b 2e 64 6c 6c 90 00 } //01 00 
		$a_00_3 = {5c 53 68 65 6c 6c 4e 6f 52 6f 61 6d 5c 4d 55 49 43 61 63 68 65 } //00 00 
	condition:
		any of ($a_*)
 
}