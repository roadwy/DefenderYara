
rule Worm_BAT_Dureelie_A{
	meta:
		description = "Worm:BAT/Dureelie.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 64 65 73 74 72 75 63 74 69 6f 6e } //1 autodestruction
		$a_01_1 = {63 72 65 65 72 46 69 63 68 69 65 72 } //1 creerFichier
		$a_01_2 = {53 65 63 61 63 68 65 72 } //1 Secacher
		$a_01_3 = {73 70 72 65 61 64 55 73 62 } //1 spreadUsb
		$a_01_4 = {74 65 6c 65 63 68 61 72 67 65 } //1 telecharge
		$a_01_5 = {3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 :\autorun.inf
		$a_01_6 = {73 00 79 00 6e 00 53 00 6f 00 63 00 6b 00 65 00 74 00 } //1 synSocket
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}