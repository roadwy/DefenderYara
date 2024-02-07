
rule Trojan_BAT_Remcos_HD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 65 65 48 69 76 65 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  BeeHiveManagementSystem.Properties.Resources
		$a_81_1 = {2f 73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 2f 2f 3a 73 70 74 74 68 } //01 00  /stnemhcatta/moc.ppadrocsid.ndc//:sptth
		$a_81_2 = {67 64 67 61 73 66 77 71 2e 67 64 67 61 73 66 77 71 } //01 00  gdgasfwq.gdgasfwq
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_5 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}