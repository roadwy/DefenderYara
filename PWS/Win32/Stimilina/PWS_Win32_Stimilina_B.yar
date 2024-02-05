
rule PWS_Win32_Stimilina_B{
	meta:
		description = "PWS:Win32/Stimilina.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 56 61 6c 76 65 5c 53 74 65 61 6d } //SOFTWARE\Valve\Steam  01 00 
		$a_80_1 = {2f 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } ///SteamAppData.vdf  01 00 
		$a_80_2 = {5c 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //\loginusers.vdf  01 00 
		$a_80_3 = {53 74 65 61 6d 20 2d 20 45 72 72 6f 72 } //Steam - Error  02 00 
		$a_80_4 = {4c 6f 67 69 6e 20 74 6f 20 73 74 65 61 6d 20 66 61 6c 65 64 2e } //Login to steam faled.  08 00 
		$a_80_5 = {73 73 66 6e 2a 2e 2a } //ssfn*.*  08 00 
		$a_80_6 = {5c 53 74 65 61 6d 32 2e 65 78 65 } //\Steam2.exe  00 00 
		$a_00_7 = {5d 04 00 00 ba 39 03 80 5c 24 00 00 bb 39 03 80 } //00 00 
	condition:
		any of ($a_*)
 
}