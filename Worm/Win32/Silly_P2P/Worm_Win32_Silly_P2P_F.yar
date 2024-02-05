
rule Worm_Win32_Silly_P2P_F{
	meta:
		description = "Worm:Win32/Silly_P2P.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 8b ec 51 83 65 fc 00 83 65 fc 00 eb 07 8b 45 fc 40 89 45 fc ff 75 08 ff 15 0c 00 41 00 39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08 c9 c3 } //01 00 
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 65 4d 75 6c 65 } //01 00 
		$a_01_2 = {5c 53 4f 46 54 57 41 52 45 5c 41 6c 74 6e 65 74 } //01 00 
		$a_03_3 = {55 54 20 32 30 30 33 20 4b 65 79 47 65 6e 2e 65 78 65 90 02 04 48 61 6c 66 2d 4c 69 66 65 20 32 20 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}