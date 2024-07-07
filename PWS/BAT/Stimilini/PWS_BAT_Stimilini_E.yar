
rule PWS_BAT_Stimilini_E{
	meta:
		description = "PWS:BAT/Stimilini.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 67 69 6e } //login  1
		$a_80_1 = {70 61 73 73 } //pass  1
		$a_80_2 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //set_UseSystemPasswordChar  1
		$a_80_3 = {61 64 64 5f 4b 65 79 50 72 65 73 73 } //add_KeyPress  1
		$a_80_4 = {53 74 65 61 72 6d 20 43 6c 69 65 6e 74 } //Stearm Client  5
		$a_80_5 = {53 74 61 65 6d 00 } //Staem  4
		$a_80_6 = {56 61 31 76 65 20 43 6f 72 70 6f 74 61 74 69 6f 6e } //Va1ve Corpotation  5
		$a_80_7 = {28 63 29 20 32 30 30 31 32 2d 32 30 31 35 20 47 61 6d 65 20 50 6c 61 74 66 6f 72 6d } //(c) 20012-2015 Game Platform  6
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*5+(#a_80_5  & 1)*4+(#a_80_6  & 1)*5+(#a_80_7  & 1)*6) >=10
 
}
rule PWS_BAT_Stimilini_E_2{
	meta:
		description = "PWS:BAT/Stimilini.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 74 61 65 72 6e 2e 65 78 65 } //Staern.exe  1
		$a_80_1 = {67 65 74 5f 73 74 65 61 6d 36 34 } //get_steam64  1
		$a_80_2 = {73 65 74 5f 53 74 65 61 6d 44 69 72 } //set_SteamDir  1
		$a_01_3 = {0e 05 20 02 01 0e 0e 0a 6c 00 6f 00 67 00 69 00 6e 00 08 70 00 61 00 73 00 73 00 0a 00 05 01 0e 0e 0e 0e } //1
		$a_03_4 = {2e 52 65 73 6f 75 72 63 65 73 00 e2 90 02 80 e2 80 ae 00 43 75 6c 74 75 72 65 49 6e 66 6f 90 00 } //1
		$a_80_5 = {68 74 74 70 3a 2f 2f 35 2e 33 39 2e 31 32 34 2e 31 37 35 2f 66 69 6c 65 73 2f 6d 6f 64 75 6c 65 2e 65 78 65 } //http://5.39.124.175/files/module.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_80_5  & 1)*1) >=4
 
}