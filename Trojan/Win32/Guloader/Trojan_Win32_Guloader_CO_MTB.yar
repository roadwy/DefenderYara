
rule Trojan_Win32_Guloader_CO_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 6e 69 74 61 72 69 69 75 6d 73 5c 47 65 6c 61 74 69 6e 61 74 69 6e 67 5c 42 75 6c 6c 66 72 6f 67 73 } //01 00  sanitariiums\Gelatinating\Bullfrogs
		$a_01_1 = {6c 75 74 65 74 69 75 6d 73 25 5c 76 61 73 63 75 6c 6f 6d 6f 74 6f 72 2e 74 61 70 } //01 00  lutetiums%\vasculomotor.tap
		$a_01_2 = {67 69 64 73 65 6c 74 61 67 6e 69 6e 67 65 72 73 2e 6e 79 74 } //01 00  gidseltagningers.nyt
		$a_01_3 = {63 68 69 61 73 6d 61 74 79 70 65 2e 74 78 74 } //01 00  chiasmatype.txt
		$a_01_4 = {4b 6e 6f 63 6b 6c 65 73 73 31 36 35 2e 6c 75 6c } //01 00  Knockless165.lul
		$a_01_5 = {6b 72 61 66 74 66 75 6c 64 68 65 64 65 72 73 5c 46 69 64 65 32 33 31 5c 72 65 63 69 74 65 64 } //01 00  kraftfuldheders\Fide231\recited
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 73 74 65 72 65 6f 74 79 70 69 65 72 6e 65 73 5c 6b 6e 6f 6b 6c 65 6e 64 65 } //01 00  Software\stereotypiernes\knoklende
		$a_01_7 = {6f 70 61 6c 65 73 63 65 73 5c 52 65 64 68 65 61 64 65 64 6e 65 73 73 2e 6c 6e 6b } //01 00  opalesces\Redheadedness.lnk
		$a_01_8 = {62 6f 6d 62 65 64 65 73 25 5c 73 65 6e 67 65 6b 61 6e 74 65 72 6e 65 5c 62 72 65 76 75 64 76 65 6b 73 6c 69 6e 67 2e 41 64 6a 39 33 } //01 00  bombedes%\sengekanterne\brevudveksling.Adj93
		$a_01_9 = {70 72 6f 74 72 65 70 74 69 63 5c 53 6c 61 67 74 65 6b 76 67 73 6d 61 72 6b 65 64 65 72 32 35 33 2e 61 67 72 } //00 00  protreptic\Slagtekvgsmarkeder253.agr
	condition:
		any of ($a_*)
 
}