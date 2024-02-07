
rule Trojan_Win32_Guloader_AJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 72 73 76 6f 72 6e 65 31 33 30 5c 54 69 73 73 73 5c 41 66 64 6b 6e 69 6e 67 2e 64 6c 6c } //01 00  Forsvorne130\Tisss\Afdkning.dll
		$a_01_1 = {42 61 6a 73 5c 54 65 67 6e 69 6e 67 73 66 72 69 73 74 65 72 6e 65 5c 43 65 72 6f 67 72 61 70 68 2e 64 6c 6c } //01 00  Bajs\Tegningsfristerne\Cerograph.dll
		$a_01_2 = {46 6f 72 62 72 75 67 65 72 6b 72 6f 6e 65 72 5c 41 6e 61 6e 69 73 6d 2e 43 6c 65 } //01 00  Forbrugerkroner\Ananism.Cle
		$a_01_3 = {45 74 68 6e 61 72 63 68 73 5c 50 6c 61 6e 6c 67 6e 69 6e 67 73 62 65 73 74 65 6d 6d 65 6c 73 65 6e 2e 68 6a 65 } //01 00  Ethnarchs\Planlgningsbestemmelsen.hje
		$a_01_4 = {42 61 73 69 73 75 64 64 61 6e 6e 65 6c 73 65 73 5c 43 61 6e 74 68 61 72 69 64 65 73 5c 42 61 6e 64 61 67 69 6e 67 2e 69 6e 69 } //01 00  Basisuddannelses\Cantharides\Bandaging.ini
		$a_01_5 = {4d 6f 72 69 63 65 5c 46 61 72 76 65 6d 6f 64 75 6c 65 74 5c 61 61 6e 64 65 64 72 61 67 65 74 73 5c 45 71 75 61 6c 69 73 65 2e 69 6e 69 } //00 00  Morice\Farvemodulet\aandedragets\Equalise.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_AJ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 64 00 65 00 6c 00 69 00 67 00 68 00 65 00 64 00 73 00 73 00 74 00 61 00 74 00 69 00 73 00 74 00 69 00 6b 00 6b 00 65 00 72 00 6e 00 65 00 2e 00 69 00 6e 00 69 00 } //01 00  ddelighedsstatistikkerne.ini
		$a_01_1 = {61 00 75 00 74 00 6f 00 76 00 61 00 73 00 6b 00 65 00 61 00 6e 00 6c 00 67 00 67 00 65 00 6e 00 65 00 73 00 5c 00 4d 00 69 00 6e 00 6b 00 31 00 37 00 36 00 } //01 00  autovaskeanlggenes\Mink176
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 49 00 6e 00 64 00 73 00 70 00 69 00 6c 00 6e 00 69 00 6e 00 67 00 65 00 72 00 73 00 5c 00 61 00 66 00 6b 00 76 00 69 00 73 00 74 00 6e 00 69 00 6e 00 67 00 65 00 72 00 } //01 00  Software\Indspilningers\afkvistninger
		$a_01_3 = {45 00 72 00 73 00 74 00 61 00 74 00 6e 00 69 00 6e 00 67 00 73 00 72 00 65 00 67 00 6c 00 65 00 72 00 6e 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //01 00  Erstatningsreglernes.ini
		$a_01_4 = {70 00 72 00 69 00 6b 00 6b 00 65 00 6e 00 64 00 65 00 73 00 5c 00 53 00 75 00 70 00 65 00 72 00 70 00 72 00 65 00 70 00 61 00 72 00 61 00 74 00 69 00 6f 00 6e 00 31 00 38 00 32 00 } //01 00  prikkendes\Superpreparation182
		$a_01_5 = {42 00 75 00 67 00 73 00 70 00 79 00 74 00 6b 00 69 00 72 00 74 00 65 00 6c 00 65 00 6e 00 73 00 2e 00 6c 00 6f 00 67 00 } //00 00  Bugspytkirtelens.log
	condition:
		any of ($a_*)
 
}