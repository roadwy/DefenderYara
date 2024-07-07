
rule PWS_Win32_Stimilina_B{
	meta:
		description = "PWS:Win32/Stimilina.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 56 61 6c 76 65 5c 53 74 65 61 6d } //SOFTWARE\Valve\Steam  1
		$a_80_1 = {2f 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } ///SteamAppData.vdf  1
		$a_80_2 = {5c 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //\loginusers.vdf  1
		$a_80_3 = {53 74 65 61 6d 20 2d 20 45 72 72 6f 72 } //Steam - Error  1
		$a_80_4 = {4c 6f 67 69 6e 20 74 6f 20 73 74 65 61 6d 20 66 61 6c 65 64 2e } //Login to steam faled.  2
		$a_80_5 = {73 73 66 6e 2a 2e 2a } //ssfn*.*  8
		$a_80_6 = {5c 53 74 65 61 6d 32 2e 65 78 65 } //\Steam2.exe  8
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*2+(#a_80_5  & 1)*8+(#a_80_6  & 1)*8) >=22
 
}