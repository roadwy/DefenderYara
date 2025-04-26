
rule PWS_BAT_Stimilina_C{
	meta:
		description = "PWS:BAT/Stimilina.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 67 00 61 00 74 00 65 00 5f 00 6e 00 65 00 77 00 2e 00 70 00 68 00 70 00 } //1 /gate_new.php
		$a_80_1 = {73 73 66 6e 2a } //ssfn*  3
		$a_01_2 = {53 74 65 61 6d 53 74 65 61 6c 65 72 } //3 SteamStealer
		$a_01_3 = {53 74 65 61 6d 57 6f 72 6b 65 72 } //3 SteamWorker
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=10
 
}
rule PWS_BAT_Stimilina_C_2{
	meta:
		description = "PWS:BAT/Stimilina.C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 74 65 61 6d 2e 65 78 65 22 20 22 25 31 22 } //steam.exe" "%1"  2
		$a_80_1 = {5c 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //\SteamAppData.vdf  2
		$a_80_2 = {5c 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } //\loginusers.vdf  2
		$a_80_3 = {5c 53 74 65 61 6d 20 43 6f 72 65 5c 2e 73 72 63 20 76 69 73 75 72 5c } //\Steam Core\.src visur\  3
		$a_80_4 = {73 73 66 6e 2a } //ssfn*  8
		$a_00_5 = {2f 00 2f 00 63 00 73 00 67 00 6f 00 6c 00 6f 00 75 00 6e 00 75 00 67 00 65 00 2e 00 6f 00 72 00 67 00 2f 00 } //11 //csgolounuge.org/
		$a_00_6 = {61 00 75 00 74 00 68 00 75 00 73 00 65 00 72 00 3d 00 30 00 26 00 69 00 64 00 3d 00 30 00 42 00 7a 00 68 00 57 00 65 00 5f 00 71 00 4b 00 37 00 35 00 77 00 4e 00 55 00 48 00 64 00 36 00 53 00 58 00 6c 00 66 00 53 00 30 00 39 00 55 00 61 00 6b 00 55 00 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //12 authuser=0&id=0BzhWe_qK75wNUHd6SXlfS09UakU&export=download
		$a_00_7 = {2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 73 00 65 00 6c 00 6c 00 65 00 78 00 70 00 6f 00 2e 00 6e 00 65 00 74 00 2f 00 } //12 //files.sellexpo.net/
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*3+(#a_80_4  & 1)*8+(#a_00_5  & 1)*11+(#a_00_6  & 1)*12+(#a_00_7  & 1)*12) >=13
 
}