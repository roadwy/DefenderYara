
rule Trojan_Win32_Fareit_PKI_MTB{
	meta:
		description = "Trojan:Win32/Fareit.PKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 6f 00 76 00 69 00 73 00 74 00 61 00 } //01 00  Bovista
		$a_01_1 = {6a 00 42 00 49 00 37 00 79 00 77 00 63 00 35 00 42 00 48 00 56 00 72 00 69 00 48 00 59 00 73 00 32 00 6c 00 46 00 48 00 74 00 4d 00 6e 00 48 00 6c 00 51 00 74 00 53 00 45 00 79 00 43 00 4f 00 33 00 33 00 31 00 36 00 39 00 } //01 00  jBI7ywc5BHVriHYs2lFHtMnHlQtSEyCO33169
		$a_01_2 = {4d 00 61 00 6e 00 69 00 6f 00 63 00 } //01 00  Manioc
		$a_01_3 = {53 00 45 00 4e 00 47 00 45 00 54 00 4a 00 45 00 54 00 } //01 00  SENGETJET
		$a_01_4 = {4e 00 6f 00 6e 00 66 00 65 00 65 00 6c 00 69 00 6e 00 67 00 6c 00 79 00 } //01 00  Nonfeelingly
		$a_01_5 = {43 00 75 00 72 00 6c 00 20 00 4c 00 61 00 73 00 74 00 69 00 6e 00 67 00 } //01 00  Curl Lasting
		$a_81_6 = {53 50 52 49 4e 4b 4c 45 4e 44 45 53 } //01 00  SPRINKLENDES
		$a_81_7 = {42 45 47 47 49 41 54 4f 41 43 45 41 45 } //01 00  BEGGIATOACEAE
		$a_81_8 = {50 72 65 64 65 63 69 64 65 64 36 } //01 00  Predecided6
		$a_81_9 = {4f 6d 73 61 64 6c 69 6e 67 65 6e 73 31 } //00 00  Omsadlingens1
	condition:
		any of ($a_*)
 
}