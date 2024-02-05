
rule PWS_Win32_OnLineGames_gen_E{
	meta:
		description = "PWS:Win32/OnLineGames.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 90 01 04 6c 73 74 72 63 61 74 41 90 02 80 4c 6f 61 64 44 4c 4c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 73 79 73 47 54 48 2e 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}