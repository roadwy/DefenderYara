
rule PWS_Win32_OnLineGames_DC{
	meta:
		description = "PWS:Win32/OnLineGames.DC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 50 66 c7 45 f0 6c 07 ff d6 68 e8 03 00 00 ff 15 90 01 02 40 00 8d 45 f0 50 ff d3 66 8b 45 e0 90 00 } //01 00 
		$a_03_1 = {0f be 04 37 8a 44 05 ac 88 04 0a ff 15 90 01 02 40 00 ff 45 fc 39 75 fc 72 bd 60 b8 0c 00 00 00 bb 0c 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}