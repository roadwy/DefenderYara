
rule Ransom_Win32_VB_Globster{
	meta:
		description = "Ransom:Win32/VB.Globster,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 18 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 65 69 6e 6b 61 72 6e 61 74 69 6f 6e 65 72 } //02 00  Reinkarnationer
		$a_01_1 = {42 79 67 6e 69 6e 67 73 76 61 65 72 6b 65 72 38 } //02 00  Bygningsvaerker8
		$a_01_2 = {43 75 72 74 61 69 6c 73 35 } //02 00  Curtails5
		$a_01_3 = {46 65 63 6b 6c 65 73 73 6e 65 73 73 } //02 00  Fecklessness
		$a_01_4 = {43 61 62 62 61 67 69 6e 67 } //02 00  Cabbaging
		$a_01_5 = {55 64 73 74 64 65 6c 73 65 6e 73 } //02 00  Udstdelsens
		$a_01_6 = {45 79 65 67 6c 61 73 73 65 73 33 } //02 00  Eyeglasses3
		$a_01_7 = {42 61 74 68 6f 63 68 72 6f 6d 65 35 } //02 00  Bathochrome5
		$a_01_8 = {55 6e 70 6c 61 6e 6e 65 64 6c 79 } //02 00  Unplannedly
		$a_01_9 = {56 65 72 73 69 66 69 63 65 72 65 73 34 } //02 00  Versificeres4
		$a_01_10 = {42 65 63 61 73 73 6f 63 6b 65 64 36 } //02 00  Becassocked6
		$a_01_11 = {56 69 64 74 73 6b 75 65 6e 64 65 30 } //02 00  Vidtskuende0
		$a_01_12 = {53 70 69 73 65 73 74 75 65 72 } //02 00  Spisestuer
		$a_01_13 = {50 61 75 73 65 72 69 6e 67 65 72 6e 65 } //02 00  Pauseringerne
		$a_01_14 = {53 75 6d 6d 61 72 69 7a 61 74 69 6f 6e 31 } //02 00  Summarization1
		$a_01_15 = {41 70 68 6f 74 69 63 35 } //02 00  Aphotic5
		$a_01_16 = {4f 76 65 72 63 61 70 69 74 61 6c 69 73 61 74 69 6f 6e } //02 00  Overcapitalisation
		$a_01_17 = {42 65 61 63 6f 6e 77 69 73 65 } //02 00  Beaconwise
		$a_01_18 = {53 6b 69 6c 6c 69 6e 67 73 74 72 79 6b 6b 65 6e 65 73 38 } //02 00  Skillingstrykkenes8
		$a_01_19 = {53 70 69 72 61 6c 62 75 6e 64 65 6e 73 } //02 00  Spiralbundens
		$a_01_20 = {53 75 62 73 74 61 6e 74 69 65 6c 6c 65 } //02 00  Substantielle
		$a_01_21 = {46 69 6c 6d 61 74 69 73 65 72 69 6e 67 65 72 } //02 00  Filmatiseringer
		$a_01_22 = {46 72 6f 75 7a 69 65 73 74 } //02 00  Frouziest
		$a_01_23 = {53 75 70 65 72 73 75 70 65 72 69 6f 72 } //00 00  Supersuperior
		$a_00_24 = {5d 04 00 00 e0 ac 03 80 5c 2e 00 00 e1 ac 03 80 00 00 01 00 } //32 00 
	condition:
		any of ($a_*)
 
}