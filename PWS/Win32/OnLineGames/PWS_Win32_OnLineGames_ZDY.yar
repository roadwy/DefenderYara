
rule PWS_Win32_OnLineGames_ZDY{
	meta:
		description = "PWS:Win32/OnLineGames.ZDY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 20 01 00 8d 20 01 00 6b 62 64 68 65 6c 61 35 2e 64 6c 6c 00 41 20 01 00 53 20 01 00 64 20 01 00 3f 41 64 64 48 6f 6f 6b 40 40 59 47 5f 4e 4b 40 5a 00 3f 44 65 6c 48 6f 6f 6b 40 40 59 47 5f 4e 58 5a 00 3f 53 63 61 6e 50 77 64 40 40 59 47 5f 4e 51 41 55 48 57 4e 44 5f 5f 40 40 30 40 5a } //00 00 
	condition:
		any of ($a_*)
 
}