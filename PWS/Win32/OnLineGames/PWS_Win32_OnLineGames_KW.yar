
rule PWS_Win32_OnLineGames_KW{
	meta:
		description = "PWS:Win32/OnLineGames.KW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 00 00 5a 45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 00 00 00 ff ff ff ff 05 00 00 00 } //04 00 
		$a_01_1 = {26 50 61 73 73 3d 00 00 ff ff ff ff 04 00 00 00 26 63 6b 3d 00 00 00 00 ff ff ff ff 04 00 00 00 26 64 6a 3d 00 00 00 00 ff ff ff ff 04 00 00 00 } //02 00 
		$a_01_2 = {53 65 6e 64 20 4f 4b 21 } //00 00 
	condition:
		any of ($a_*)
 
}