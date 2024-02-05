
rule PWS_Win32_OnLineGames_CPW{
	meta:
		description = "PWS:Win32/OnLineGames.CPW,SIGNATURE_TYPE_PEHSTR_EXT,47 00 47 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {76 62 36 63 68 73 2e 64 6c 6c } //0a 00 
		$a_80_1 = {2e 76 62 70 } //.vbp  0a 00 
		$a_80_2 = {52 65 63 79 63 6c 65 64 2e 65 78 65 } //Recycled.exe  0a 00 
		$a_80_3 = {6d 73 76 63 69 2e 65 78 65 } //msvci.exe  0a 00 
		$a_01_4 = {47 61 76 70 73 } //0a 00 
		$a_00_5 = {46 69 6e 64 57 69 6e 64 6f 77 41 } //0a 00 
		$a_00_6 = {53 65 74 57 69 6e 64 6f 77 4c 6f 6e 67 41 } //01 00 
		$a_01_7 = {63 68 61 74 72 72 00 00 74 6f 61 74 72 72 00 00 64 65 6c 66 69 6c 65 00 63 6f 70 79 } //01 00 
		$a_80_8 = {6c 65 67 65 6e 64 20 6f 66 20 6d 69 72 32 } //legend of mir2  00 00 
	condition:
		any of ($a_*)
 
}