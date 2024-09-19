
rule Trojan_Win32_CleanUpLoader_DB_MTB{
	meta:
		description = "Trojan:Win32/CleanUpLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 62 61 74 20 26 20 65 78 69 74 } //1 .bat & exit
		$a_81_1 = {57 65 61 70 6f 6e 53 71 75 69 72 74 46 69 6e 67 65 72 69 6e 67 50 69 73 73 52 69 70 65 44 69 65 73 65 6c } //1 WeaponSquirtFingeringPissRipeDiesel
		$a_81_2 = {43 6f 6c 6c 65 63 74 6f 72 73 4d 69 6c 6c 69 6f 6e 73 43 61 72 67 6f 4d 75 73 65 75 6d 73 53 6c 6f 77 } //1 CollectorsMillionsCargoMuseumsSlow
		$a_81_3 = {59 65 73 4a 61 70 61 6e 41 6e 67 6c 65 43 67 69 54 65 72 72 61 63 65 } //1 YesJapanAngleCgiTerrace
		$a_81_4 = {47 6f 74 6f 52 65 61 73 6f 6e 73 4a 6f 73 68 41 70 70 6f 69 6e 74 65 64 4d 61 73 74 65 72 63 61 72 64 43 61 6c 69 66 6f 72 6e 69 61 } //1 GotoReasonsJoshAppointedMastercardCalifornia
		$a_81_5 = {42 61 73 6b 65 74 62 61 6c 6c } //1 Basketball
		$a_81_6 = {4c 6f 75 69 73 76 69 6c 6c 65 43 6f 61 63 68 } //1 LouisvilleCoach
		$a_81_7 = {43 6f 70 79 20 44 65 74 61 69 6c 73 20 54 6f 20 43 6c 69 70 62 6f 61 72 64 } //1 Copy Details To Clipboard
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}