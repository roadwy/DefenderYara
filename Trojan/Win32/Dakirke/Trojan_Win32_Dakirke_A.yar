
rule Trojan_Win32_Dakirke_A{
	meta:
		description = "Trojan:Win32/Dakirke.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 66 6f 6e 62 72 75 73 65 72 65 73 36 } //01 00  Telefonbruseres6
		$a_01_1 = {6d 75 63 69 6c 61 67 65 } //01 00  mucilage
		$a_01_2 = {55 6e 61 70 70 72 65 68 65 6e 64 69 6e 67 } //01 00  Unapprehending
		$a_01_3 = {6b 69 72 6b 65 67 61 61 72 64 73 6c 65 64 65 72 73 } //01 00  kirkegaardsleders
		$a_01_4 = {53 69 72 70 6c 61 6e 74 65 72 6e 65 73 } //01 00  Sirplanternes
		$a_01_5 = {41 67 6f 6e 69 65 6e } //01 00  Agonien
		$a_01_6 = {45 78 6f 63 6f 65 6c 6f 6d 37 } //01 00  Exocoelom7
		$a_01_7 = {52 41 50 50 4f 52 54 45 52 49 4e 47 45 52 4e 45 } //01 00  RAPPORTERINGERNE
		$a_01_8 = {49 6e 66 69 6c 74 72 65 } //01 00  Infiltre
		$a_01_9 = {46 6f 72 6d 5f 50 61 69 6e 74 } //01 00  Form_Paint
		$a_01_10 = {53 74 61 72 74 53 79 73 49 6e 66 6f } //00 00  StartSysInfo
	condition:
		any of ($a_*)
 
}