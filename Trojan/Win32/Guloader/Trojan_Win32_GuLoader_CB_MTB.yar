
rule Trojan_Win32_GuLoader_CB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {62 6c 61 6d 61 62 69 6c 69 74 79 2e 64 61 74 } //03 00  blamability.dat
		$a_81_1 = {77 73 6f 63 6b 33 32 3a 3a 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 28 74 20 27 42 69 73 79 6d 6d 65 74 72 69 63 32 34 37 27 29 } //03 00  wsock32::gethostbyname(t 'Bisymmetric247')
		$a_81_2 = {75 73 65 72 33 32 3a 3a 47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 28 69 20 32 34 39 29 } //03 00  user32::GetKeyboardType(i 249)
		$a_81_3 = {6b 65 72 6e 65 6c 33 32 3a 3a 53 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 28 74 20 27 61 72 74 69 73 74 65 72 6e 65 73 27 29 } //03 00  kernel32::SetComputerNameA(t 'artisternes')
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 61 66 6c 62 73 62 72 6e 64 65 6e 65 73 5c 4f 72 65 78 69 73 } //03 00  Software\aflbsbrndenes\Orexis
		$a_81_5 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllUnregisterServer
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_GuLoader_CB_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 75 72 69 74 75 73 5c 55 6e 68 75 73 6b 61 62 6c 65 5c 4f 70 67 72 65 6c 73 65 72 2e 53 74 79 } //01 00  Pruritus\Unhuskable\Opgrelser.Sty
		$a_01_1 = {53 61 6e 67 65 72 65 73 5c 54 72 65 64 76 65 61 61 72 73 64 61 67 65 73 5c 41 75 74 6f 6d 61 74 74 65 6f 72 69 65 6e 2e 69 6e 69 } //01 00  Sangeres\Tredveaarsdages\Automatteorien.ini
		$a_01_2 = {42 65 73 76 72 6c 69 67 67 72 65 6c 73 65 72 6e 65 5c 50 69 78 69 6e 65 73 73 2e 49 6e 76 } //01 00  Besvrliggrelserne\Pixiness.Inv
		$a_01_3 = {41 6c 75 6d 69 6e 5c 53 74 75 64 69 65 67 6c 64 73 5c 53 74 61 74 73 61 6d 74 65 72 6e 65 73 5c 4e 6f 6e 65 67 72 65 67 69 6f 75 73 6e 65 73 73 2e 69 6e 69 } //01 00  Alumin\Studieglds\Statsamternes\Nonegregiousness.ini
		$a_01_4 = {4e 72 69 6e 67 73 6d 61 74 65 72 69 61 6c 65 72 6e 65 73 32 32 39 2e 69 6e 69 } //01 00  Nringsmaterialernes229.ini
		$a_01_5 = {53 6b 69 62 73 76 72 66 74 65 74 73 5c 46 65 61 74 68 65 72 66 6f 69 6c 2e 69 6e 69 } //01 00  Skibsvrftets\Featherfoil.ini
		$a_01_6 = {48 61 72 6d 6f 6e 69 73 65 72 69 6e 67 73 5c 43 6f 6d 70 61 73 73 6d 65 6e 74 33 2e 6c 6e 6b } //01 00  Harmoniserings\Compassment3.lnk
		$a_01_7 = {50 61 6e 74 68 65 61 5c 42 69 6e 6f 63 75 6c 61 72 73 5c 61 66 73 6c 75 74 6e 69 6e 67 65 6e 73 5c 48 61 6e 64 65 6c 73 68 69 6e 64 72 69 6e 67 65 72 6e 65 2e 55 6e 66 31 34 31 } //01 00  Panthea\Binoculars\afslutningens\Handelshindringerne.Unf141
		$a_01_8 = {55 6e 6d 75 6c 6c 69 6f 6e 65 64 5c 55 61 6e 6d 65 6c 64 74 65 5c 4e 6f 72 64 61 6d 65 72 69 6b 61 6e 73 6b 5c 4b 6e 6f 67 6c 65 6c 65 64 65 74 73 2e 69 6e 69 } //01 00  Unmullioned\Uanmeldte\Nordamerikansk\Knogleledets.ini
		$a_01_9 = {72 6b 6b 65 68 75 73 65 74 73 5c 4e 79 74 74 65 74 5c 47 61 6c 6f 70 69 6e 67 2e 4b 6e 6f } //01 00  rkkehusets\Nyttet\Galoping.Kno
		$a_01_10 = {42 6c 72 65 72 6f 64 65 6e 5c 4b 65 72 6e 65 72 65 61 6b 74 6f 72 65 6e 73 2e 64 6c 6c } //01 00  Blreroden\Kernereaktorens.dll
		$a_01_11 = {50 75 72 65 65 6e 5c 4e 65 74 74 69 5c 50 79 6c 6f 72 61 6c 67 69 61 2e 64 6c 6c } //00 00  Pureen\Netti\Pyloralgia.dll
	condition:
		any of ($a_*)
 
}