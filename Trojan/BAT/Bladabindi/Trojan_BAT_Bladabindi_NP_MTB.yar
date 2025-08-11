
rule Trojan_BAT_Bladabindi_NP_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 5f 53 68 69 74 74 65 64 5f 4d 79 5f 53 65 6c 66 2e 65 78 65 } //2 i_Shitted_My_Self.exe
		$a_01_1 = {73 00 4b 00 69 00 44 00 74 00 4f 00 6f 00 4c 00 73 00 5f 00 57 00 68 00 59 00 5f 00 75 00 5f 00 4c 00 6f 00 4f 00 6b 00 49 00 67 00 5f 00 48 00 65 00 52 00 65 00 } //2 sKiDtOoLs_WhY_u_LoOkIg_HeRe
		$a_01_2 = {53 00 68 00 6f 00 70 00 43 00 68 00 6f 00 70 00 23 00 36 00 39 00 33 00 36 00 } //1 ShopChop#6936
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Bladabindi_NP_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 36 37 2e 37 31 2e 31 34 2e 31 33 35 } //2 http://167.71.14.135
		$a_81_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 22 73 76 63 68 6f 73 74 2e 65 78 65 22 } //1 Add-MpPreference -ExclusionProcess "svchost.exe"
		$a_81_2 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
		$a_81_3 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 27 3b 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 55 73 65 72 73 } //1 AppData\Roaming\Microsoft\Windows';Add-MpPreference -ExclusionPath 'C:\Users
		$a_81_4 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 2e 65 78 65 } //1 Microsoft\Windows\Windows.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}