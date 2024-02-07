
rule Trojan_BAT_Frel_A{
	meta:
		description = "Trojan:BAT/Frel.A,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 69 74 6c 65 20 41 76 61 73 74 21 20 56 69 72 75 73 20 41 6c 65 72 74 } //01 00  Title Avast! Virus Alert
		$a_01_1 = {65 63 68 6f 20 55 6e 20 76 69 72 75 73 20 61 20 65 74 65 20 64 65 74 65 63 74 65 20 73 75 72 20 76 6f 74 72 65 20 6f 72 64 69 6e 61 74 65 75 72 } //01 00  echo Un virus a ete detecte sur votre ordinateur
		$a_01_2 = {69 66 20 25 69 6e 70 75 74 25 3d 3d 6f 20 67 6f 74 6f 20 6f } //01 00  if %input%==o goto o
		$a_01_3 = {65 63 68 6f 20 56 6f 75 73 20 76 6f 75 73 20 65 74 65 20 66 61 69 74 20 70 72 65 6e 64 72 65 20 70 61 72 20 73 65 20 66 61 75 78 20 76 69 72 75 73 20 69 6e 6e 6f 66 65 6e 73 69 66 20 } //01 00  echo Vous vous ete fait prendre par se faux virus innofensif 
		$a_01_4 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 34 20 3e 20 6e 75 6c } //01 00  ping localhost -n 4 > nul
		$a_01_5 = {65 63 68 6f 20 43 6f 64 65 20 50 49 4e 20 63 6f 72 72 65 63 74 } //00 00  echo Code PIN correct
	condition:
		any of ($a_*)
 
}