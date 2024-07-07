
rule PWS_Win32_Stimilini_K{
	meta:
		description = "PWS:Win32/Stimilini.K,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 72 00 6b 00 7a 00 69 00 65 00 6c 00 5f 00 66 00 6f 00 72 00 6d 00 } //1 derkziel_form
		$a_01_1 = {64 65 72 6b 7a 69 65 6c 2e 74 78 74 } //1 derkziel.txt
		$a_01_2 = {73 73 66 6e 2a } //1 ssfn*
		$a_01_3 = {63 6f 6e 66 69 67 5c 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //1 config\SteamAppData.vdf
		$a_01_4 = {23 21 61 63 74 69 21 23 } //1 #!acti!#
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}