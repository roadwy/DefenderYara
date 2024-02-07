
rule Trojan_O97M_Donoff_PWC_MTB{
	meta:
		description = "Trojan:O97M/Donoff.PWC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 48 41 52 28 31 30 34 29 26 22 74 74 70 73 3a 2f 2f 77 77 77 2e 73 65 79 72 61 6e 69 6b 65 6e 67 65 72 2e 63 6f 6d 2e 74 72 2f 6d 65 6e 73 61 6a 65 72 69 61 5f 73 79 73 74 65 6d 2e 65 78 65 } //01 00  CHAR(104)&"ttps://www.seyranikenger.com.tr/mensajeria_system.exe
		$a_01_1 = {43 3a 5c 22 20 26 20 43 68 61 72 28 38 30 29 20 26 20 43 68 61 72 28 38 32 29 20 26 20 22 4f 47 52 41 4d 44 41 54 41 5c 61 2e 22 26 43 48 41 52 28 31 30 31 29 26 22 78 65 22 29 } //01 00  C:\" & Char(80) & Char(82) & "OGRAMDATA\a."&CHAR(101)&"xe")
		$a_01_2 = {28 22 75 72 22 26 43 48 41 52 28 31 30 38 29 26 22 6d 6f 6e 22 2c 22 55 52 22 26 43 48 41 52 28 37 36 29 26 22 44 6f 77 6e 22 26 43 48 41 52 28 31 30 38 29 26 22 6f 61 64 54 6f 46 69 22 26 43 48 41 52 28 31 30 38 29 26 22 65 41 } //01 00  ("ur"&CHAR(108)&"mon","UR"&CHAR(76)&"Down"&CHAR(108)&"oadToFi"&CHAR(108)&"eA
		$a_01_3 = {4a 4a 43 43 4a 4a } //00 00  JJCCJJ
	condition:
		any of ($a_*)
 
}