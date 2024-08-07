
rule PWS_Win32_Stimilina_A{
	meta:
		description = "PWS:Win32/Stimilina.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 56 61 6c 76 65 5c 53 74 65 61 6d } //SOFTWARE\Valve\Steam  1
		$a_80_1 = {53 74 65 61 6d 50 61 74 68 } //SteamPath  1
		$a_80_2 = {2f 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } ///SteamAppData.vdf  1
		$a_80_3 = {73 73 66 6e 2a } //ssfn*  2
		$a_80_4 = {73 74 65 61 6d 63 6f 6d 6e 75 6e 69 74 79 } //steamcomnunity  5
		$a_80_5 = {73 74 65 61 6d 63 6f 6d 6d 75 6d 6e 69 74 74 79 } //steamcommumnitty  5
		$a_80_6 = {73 74 65 61 6d 63 6f 6d 6d 75 6e 6e 69 74 74 79 } //steamcommunnitty  5
		$a_00_7 = {73 74 65 61 6d 72 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d } //5 steamrommunity.com
		$a_00_8 = {73 74 65 61 7a 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d } //5 steazommunity.com
		$a_80_9 = {2f 73 73 66 6e 55 70 6c 6f 61 64 } ///ssfnUpload  5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5+(#a_80_9  & 1)*5) >=8
 
}
rule PWS_Win32_Stimilina_A_2{
	meta:
		description = "PWS:Win32/Stimilina.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 66 69 67 2f 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //1 config/SteamAppData.vdf
		$a_01_1 = {2f 6d 61 72 6b 65 74 2f 65 6c 69 67 69 62 69 6c 69 74 79 63 68 65 63 6b 2f 3f 67 6f 74 6f 3d } //1 /market/eligibilitycheck/?goto=
		$a_01_2 = {2f 50 61 72 73 65 49 6e 76 3f 69 64 3d } //1 /ParseInv?id=
		$a_01_3 = {41 6c 65 78 5c 64 6f 63 75 6d 65 6e 74 73 5c } //1 Alex\documents\
		$a_01_4 = {2f 68 61 6c 66 5f 6c 69 66 65 5f 33 2f 69 6e 64 65 78 2e 70 68 70 } //1 /half_life_3/index.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}