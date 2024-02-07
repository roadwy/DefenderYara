
rule Trojan_Win32_Guloader_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 0c 1e 81 90 02 20 90 13 90 02 20 81 f1 90 02 20 90 13 90 02 10 31 0c 1f 90 02 20 81 c3 90 02 10 90 13 90 02 10 81 eb 90 02 10 90 13 90 02 20 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 70 00 61 00 6e 00 69 00 65 00 6c 00 73 00 5c 00 43 00 68 00 6f 00 6c 00 65 00 63 00 79 00 73 00 74 00 65 00 63 00 74 00 6f 00 6d 00 69 00 7a 00 65 00 64 00 39 00 33 00 5c 00 61 00 62 00 6c 00 75 00 76 00 69 00 6f 00 6e 00 } //01 00  spaniels\Cholecystectomized93\abluvion
		$a_01_1 = {70 00 69 00 70 00 70 00 65 00 6e 00 64 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  pippendes.ini
		$a_01_2 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 73 00 75 00 67 00 67 00 65 00 73 00 74 00 69 00 76 00 69 00 74 00 65 00 74 00 73 00 } //01 00  CurrentVersion\Uninstall\suggestivitets
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 45 00 4d 00 41 00 52 00 43 00 41 00 54 00 4f 00 52 00 53 00 5c 00 50 00 52 00 4f 00 54 00 45 00 41 00 43 00 45 00 41 00 45 00 } //01 00  Software\DEMARCATORS\PROTEACEAE
		$a_01_4 = {56 00 74 00 67 00 64 00 69 00 33 00 6c 00 41 00 } //00 00  Vtgdi3lA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 75 64 64 61 39 31 } //01 00  Gudda91
		$a_01_1 = {55 6b 75 6e 73 74 6e 65 72 69 73 6b 37 31 } //01 00  Ukunstnerisk71
		$a_01_2 = {42 6c 6f 6d 73 74 65 72 6b 6f 73 74 65 73 35 31 } //01 00  Blomsterkostes51
		$a_01_3 = {4d 61 72 65 6b 61 6e 69 74 65 31 } //01 00  Marekanite1
		$a_01_4 = {52 44 56 49 4e 53 47 4c 41 53 53 45 4e 45 53 31 } //01 00  RDVINSGLASSENES1
		$a_01_5 = {68 61 6e 6b 73 } //01 00  hanks
		$a_01_6 = {32 32 31 32 31 37 31 31 35 31 35 31 5a 30 } //01 00  221217115151Z0
		$a_01_7 = {33 31 30 31 30 36 30 30 30 30 30 30 5a 30 48 31 } //00 00  310106000000Z0H1
	condition:
		any of ($a_*)
 
}