
rule Trojan_BAT_Kryptik_SK_eml{
	meta:
		description = "Trojan:BAT/Kryptik.SK!eml,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 2e 70 64 62 90 0a 58 00 43 3a 5c 55 73 65 72 73 5c 53 61 6b 6f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 4e 76 69 64 69 61 43 61 74 61 6c 79 73 74 73 5c 6f 62 6a 5c 44 65 62 75 67 90 00 } //01 00 
		$a_00_1 = {63 3a 5c 74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } //00 00  c:\temp\Assembly.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Kryptik_SK_eml_2{
	meta:
		description = "Trojan:BAT/Kryptik.SK!eml,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 6d 00 70 00 6c 00 65 00 53 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  SimpleSchool.exe
		$a_01_1 = {53 00 69 00 6d 00 70 00 6c 00 65 00 53 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  SimpleSchool.Properties.Resources
		$a_01_2 = {63 00 6f 00 75 00 72 00 73 00 65 00 44 00 41 00 54 00 65 00 73 00 74 00 54 00 6f 00 6f 00 6c 00 53 00 74 00 72 00 69 00 70 00 4d 00 65 00 6e 00 75 00 49 00 74 00 65 00 6d 00 } //00 00  courseDATestToolStripMenuItem
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Kryptik_SK_eml_3{
	meta:
		description = "Trojan:BAT/Kryptik.SK!eml,SIGNATURE_TYPE_PEHSTR,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 00 75 00 65 00 73 00 73 00 54 00 68 00 65 00 41 00 6e 00 69 00 6d 00 61 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  GuessTheAnimal.exe
		$a_01_1 = {54 00 6f 00 77 00 65 00 72 00 43 00 6f 00 72 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  TowerCorner.exe
		$a_01_2 = {43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 6f 00 72 00 42 00 69 00 6e 00 61 00 72 00 69 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  CalculatorBinaries.exe
		$a_01_3 = {41 00 6d 00 61 00 64 00 65 00 75 00 73 00 5a 00 65 00 75 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  AmadeusZeus.exe
		$a_01_4 = {41 00 6e 00 69 00 6d 00 61 00 6c 00 47 00 61 00 6d 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //00 00  AnimalGames.exe
	condition:
		any of ($a_*)
 
}