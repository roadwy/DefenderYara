
rule Trojan_BAT_Remcos_GY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 61 72 5f 72 65 6e 74 61 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 car_rental.Properties.Resources
		$a_81_1 = {53 55 50 52 41 41 41 41 41 41 41 41 } //1 SUPRAAAAAAAA
		$a_81_2 = {6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 2f 2f 3a 73 70 74 74 68 } //1 moc.ppadrocsid.ndc//:sptth
		$a_81_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_5 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}