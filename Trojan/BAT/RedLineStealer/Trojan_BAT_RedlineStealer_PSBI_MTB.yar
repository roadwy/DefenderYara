
rule Trojan_BAT_RedlineStealer_PSBI_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.PSBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {00 06 16 2e 16 12 00 12 01 12 02 7e 06 00 00 04 06 97 29 1a 00 00 11 0d 00 2b e5 } //02 00 
		$a_01_1 = {62 68 61 75 70 61 64 76 66 76 78 56 74 6f 75 6f 6a 6f 61 75 70 61 64 76 66 76 78 56 74 6f 75 6f 6a 6f 61 75 70 61 64 76 66 76 78 55 44 66 75 78 6a 6f 61 75 70 61 64 61 4b 73 64 7b 7d 44 7b 47 68 6f 61 73 5b } //02 00  bhaupadvfvxVtouojoaupadvfvxVtouojoaupadvfvxUDfuxjoaupadaKsd{}D{Ghoas[
		$a_01_2 = {75 6f 7a 6f 61 75 70 71 64 76 76 76 78 56 74 6f 75 } //02 00  uozoaupqdvvvxVtou
		$a_01_3 = {6a 6f 61 75 70 61 64 76 66 76 78 } //02 00  joaupadvfvx
		$a_01_4 = {6b 64 76 64 76 78 56 74 6f 75 6f 6a 6f 61 75 70 61 64 56 66 76 } //02 00  kdvdvxVtouojoaupadVfv
		$a_01_5 = {6e 61 74 70 61 64 76 66 76 78 } //01 00  natpadvfvx
		$a_01_6 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d 45 78 65 63 75 74 65 } //01 00  ICryptoTransformExecute
		$a_01_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_8 = {44 61 72 6b 59 65 6c 6c 6f 77 54 6f 42 79 74 65 41 72 72 61 79 } //00 00  DarkYellowToByteArray
	condition:
		any of ($a_*)
 
}