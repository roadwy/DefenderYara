
rule TrojanDropper_O97M_AveMaria_BAK_MTB{
	meta:
		description = "TrojanDropper:O97M/AveMaria.BAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 20 53 75 62 20 44 4f 43 55 4d 65 6e 54 5f 6f 70 65 4e 28 29 } //1 Static Sub DOCUMenT_opeN()
		$a_01_1 = {43 61 6c 6c 20 64 66 6d 7a 7a 6b 67 45 67 49 54 67 75 42 7a 56 70 65 65 3a 20 45 6e 64 20 53 75 62 } //1 Call dfmzzkgEgITguBzVpee: End Sub
		$a_01_2 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 24 28 72 74 74 72 74 72 68 74 68 74 72 79 79 79 2e 4f 70 74 69 6f 6e 42 75 74 74 6f 66 66 67 66 64 67 64 66 67 67 67 67 6e 31 2e 47 72 6f 75 70 4e 61 6d 65 2c 20 76 62 48 69 64 65 29 } //1 Call VBA.Shell$(rttrtrhthtryyy.OptionButtoffgfdgdfggggn1.GroupName, vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}