
rule Trojan_Win32_Guloader_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 0c 1e 81 [0-20] 90 13 [0-20] 81 f1 [0-20] 90 13 [0-10] 31 0c 1f [0-20] 81 c3 [0-10] 90 13 [0-10] 81 eb [0-10] 90 13 [0-20] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 72 70 6f 72 61 32 32 30 2e 46 69 6c } //1 Corpora220.Fil
		$a_01_1 = {62 65 73 74 6e 69 6e 67 73 6d 65 64 6c 65 6d 2e 63 68 61 } //1 bestningsmedlem.cha
		$a_01_2 = {70 6f 6c 6c 69 6e 6f 73 69 73 2e 4b 74 74 } //1 pollinosis.Ktt
		$a_01_3 = {75 6e 73 77 61 79 61 62 6c 65 6e 65 73 73 } //1 unswayableness
		$a_01_4 = {73 69 64 65 68 6e 67 74 65 2e 69 6e 69 } //1 sidehngte.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 64 6d 6f 64 65 72 65 6e 2e 64 6c 6c } //1 Madmoderen.dll
		$a_01_1 = {43 61 62 6d 65 6e 5c 61 66 68 75 64 65 74 } //1 Cabmen\afhudet
		$a_01_2 = {77 6f 72 74 68 77 68 69 6c 65 6e 65 73 73 } //1 worthwhileness
		$a_01_3 = {6f 76 65 72 6a 65 67 65 72 73 } //1 overjegers
		$a_01_4 = {53 75 6b 6b 65 72 6b 75 67 6c 65 72 6e 65 73 32 30 31 2e 68 65 72 } //1 Sukkerkuglernes201.her
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6f 6f 74 69 65 73 2e 72 77 61 } //1 footies.rwa
		$a_01_1 = {6e 6f 6e 63 68 61 72 67 65 61 62 6c 65 2e 66 61 6c } //1 nonchargeable.fal
		$a_01_2 = {73 69 6c 6b 65 70 61 70 69 72 73 2e 67 75 6c } //1 silkepapirs.gul
		$a_01_3 = {72 65 76 61 6c 69 64 65 72 69 6e 67 73 63 65 6e 74 72 65 73 2e 62 72 75 } //1 revalideringscentres.bru
		$a_01_4 = {53 75 7a 61 6e 6e 61 68 } //1 Suzannah
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 69 6f 6e 70 6c 61 6e 72 65 74 6e 69 6e 67 73 6c 69 6e 6a 65 72 } //1 regionplanretningslinjer
		$a_01_1 = {73 6c 65 74 68 76 61 72 72 65 72 73 } //1 slethvarrers
		$a_01_2 = {67 79 6e 61 6e 64 72 6f 6d 6f 72 70 68 79 } //1 gynandromorphy
		$a_01_3 = {73 65 6b 72 65 74 61 72 69 61 74 73 6d 65 64 61 72 62 65 6a 64 65 72 65 6e } //1 sekretariatsmedarbejderen
		$a_01_4 = {54 61 61 73 74 72 75 70 67 61 61 72 64 32 33 30 } //1 Taastrupgaard230
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_6{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 70 00 61 00 6e 00 69 00 65 00 6c 00 73 00 5c 00 43 00 68 00 6f 00 6c 00 65 00 63 00 79 00 73 00 74 00 65 00 63 00 74 00 6f 00 6d 00 69 00 7a 00 65 00 64 00 39 00 33 00 5c 00 61 00 62 00 6c 00 75 00 76 00 69 00 6f 00 6e 00 } //1 spaniels\Cholecystectomized93\abluvion
		$a_01_1 = {70 00 69 00 70 00 70 00 65 00 6e 00 64 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //1 pippendes.ini
		$a_01_2 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 73 00 75 00 67 00 67 00 65 00 73 00 74 00 69 00 76 00 69 00 74 00 65 00 74 00 73 00 } //1 CurrentVersion\Uninstall\suggestivitets
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 45 00 4d 00 41 00 52 00 43 00 41 00 54 00 4f 00 52 00 53 00 5c 00 50 00 52 00 4f 00 54 00 45 00 41 00 43 00 45 00 41 00 45 00 } //1 Software\DEMARCATORS\PROTEACEAE
		$a_01_4 = {56 00 74 00 67 00 64 00 69 00 33 00 6c 00 41 00 } //1 Vtgdi3lA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_7{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 75 64 64 61 39 31 } //1 Gudda91
		$a_01_1 = {55 6b 75 6e 73 74 6e 65 72 69 73 6b 37 31 } //1 Ukunstnerisk71
		$a_01_2 = {42 6c 6f 6d 73 74 65 72 6b 6f 73 74 65 73 35 31 } //1 Blomsterkostes51
		$a_01_3 = {4d 61 72 65 6b 61 6e 69 74 65 31 } //1 Marekanite1
		$a_01_4 = {52 44 56 49 4e 53 47 4c 41 53 53 45 4e 45 53 31 } //1 RDVINSGLASSENES1
		$a_01_5 = {68 61 6e 6b 73 } //1 hanks
		$a_01_6 = {32 32 31 32 31 37 31 31 35 31 35 31 5a 30 } //1 221217115151Z0
		$a_01_7 = {33 31 30 31 30 36 30 30 30 30 30 30 5a 30 48 31 } //1 310106000000Z0H1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}