
rule Trojan_Win32_Guloader_SA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 63 00 6b 00 70 00 69 00 74 00 74 00 65 00 72 00 6e 00 65 00 73 00 } //01 00  Cockpitternes
		$a_01_1 = {53 00 63 00 6c 00 65 00 72 00 6f 00 74 00 6f 00 69 00 64 00 36 00 } //01 00  Sclerotoid6
		$a_01_2 = {46 00 6f 00 72 00 73 00 6b 00 6e 00 69 00 6e 00 67 00 73 00 70 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 65 00 72 00 6e 00 65 00 31 00 } //01 00  Forskningsprojekterne1
		$a_01_3 = {74 00 65 00 67 00 6e 00 65 00 73 00 65 00 72 00 69 00 65 00 6d 00 65 00 73 00 74 00 72 00 65 00 73 00 } //01 00  tegneseriemestres
		$a_01_4 = {47 00 65 00 6e 00 6e 00 65 00 6d 00 61 00 72 00 62 00 65 00 6a 00 64 00 65 00 72 00 } //01 00  Gennemarbejder
		$a_01_5 = {66 00 6c 00 65 00 72 00 62 00 72 00 75 00 67 00 65 00 72 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 65 00 6e 00 } //00 00  flerbrugerinstallationen
	condition:
		any of ($a_*)
 
}