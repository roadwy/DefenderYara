
rule PWS_Win32_OnLineGames_GC{
	meta:
		description = "PWS:Win32/OnLineGames.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ac 0a c0 74 03 32 45 10 aa 80 3e 00 75 06 80 7e 01 00 74 02 eb ea } //01 00 
		$a_03_1 = {89 45 94 6a 00 6a 18 8d 45 98 50 6a 00 ff 75 94 e8 90 01 02 00 00 0b c0 75 72 ff 75 ac 6a 00 68 00 04 00 00 e8 90 01 02 00 00 0b c0 74 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}