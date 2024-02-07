
rule Trojan_Win32_Guloader_AK_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0f 85 d2 e8 90 01 02 00 00 85 c0 39 c1 75 90 01 01 eb 90 00 } //01 00 
		$a_01_1 = {eb 02 00 00 ff e0 } //01 00 
		$a_01_2 = {0f 6e da 66 85 db 31 f1 85 ff c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 6f 00 74 00 31 00 33 00 2e 00 63 00 } //01 00  rot13.c
		$a_01_1 = {76 00 69 00 65 00 77 00 2d 00 6c 00 69 00 73 00 74 00 2d 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 73 00 76 00 67 00 } //01 00  view-list-symbolic.svg
		$a_01_2 = {32 00 38 00 2e 00 32 00 35 00 2e 00 31 00 } //01 00  28.25.1
		$a_01_3 = {47 00 41 00 52 00 42 00 41 00 47 00 45 00 53 00 54 00 52 00 49 00 4e 00 47 00 42 00 4c 00 4f 00 43 00 4b 00 } //01 00  GARBAGESTRINGBLOCK
		$a_01_4 = {58 00 4f 00 52 00 53 00 54 00 52 00 49 00 4e 00 47 00 50 00 41 00 53 00 53 00 } //01 00  XORSTRINGPASS
		$a_01_5 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 3a 00 3a 00 53 00 77 00 69 00 74 00 63 00 68 00 54 00 6f 00 54 00 68 00 72 00 65 00 61 00 64 00 28 00 29 00 } //01 00  kernel32.dll::SwitchToThread()
		$a_01_6 = {41 00 64 00 76 00 65 00 6e 00 74 00 75 00 72 00 65 00 5f 00 31 00 38 00 2e 00 62 00 6d 00 70 00 } //00 00  Adventure_18.bmp
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_AK_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 75 6e 6b 65 6e 73 5c 53 65 72 6f 74 79 70 65 73 5c 49 6e 73 65 63 61 62 6c 65 2e 6c 6e 6b } //01 00  Munkens\Serotypes\Insecable.lnk
		$a_01_1 = {55 64 73 6f 6c 67 74 65 73 5c 53 6b 75 64 67 61 72 6e 73 5c 49 64 65 6e 74 69 74 65 74 73 66 6c 65 6c 73 65 2e 42 65 6c } //01 00  Udsolgtes\Skudgarns\Identitetsflelse.Bel
		$a_01_2 = {53 70 61 72 74 6c 69 6e 67 73 5c 54 72 6f 70 73 66 72 65 72 65 6e 73 5c 44 65 73 6f 6c 61 74 65 6c 79 5c 50 6c 65 73 6b 65 6e 65 72 6e 65 2e 41 6d 62 } //01 00  Spartlings\Tropsfrerens\Desolately\Pleskenerne.Amb
		$a_01_3 = {4c 79 67 74 65 72 6e 65 5c 49 6c 6f 6e 61 5c 41 62 73 63 69 73 73 69 6f 6e 73 2e 42 72 64 } //01 00  Lygterne\Ilona\Abscissions.Brd
		$a_01_4 = {56 65 6a 6c 65 64 6e 69 6e 67 65 6e 73 5c 53 74 79 72 65 74 6a 73 6b 6f 6e 74 72 6f 6c 6c 65 6e 73 5c 41 75 74 6f 64 61 66 73 78 65 72 73 5c 4d 65 61 7a 65 6c 2e 64 6c 6c } //01 00  Vejledningens\Styretjskontrollens\Autodafsxers\Meazel.dll
		$a_01_5 = {44 6f 70 70 65 64 5c 44 72 6d 6d 65 72 73 32 35 31 5c 44 61 61 73 65 73 61 67 2e 69 6e 69 } //00 00  Dopped\Drmmers251\Daasesag.ini
	condition:
		any of ($a_*)
 
}