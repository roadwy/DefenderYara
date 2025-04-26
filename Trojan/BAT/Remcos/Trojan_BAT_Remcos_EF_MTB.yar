
rule Trojan_BAT_Remcos_EF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 07 72 86 75 00 70 28 04 00 00 06 18 14 28 07 00 00 0a 0c 08 72 9c 75 00 70 28 04 00 00 06 17 18 8d 01 00 00 01 0d 09 16 16 8c 0c 00 00 01 a2 09 28 07 00 00 0a 26 2a } //1
		$a_01_1 = {70 0a 02 6f 17 00 00 0a 17 59 0b 2b 17 06 02 07 6f 18 00 00 0a 8c 20 00 00 01 28 19 00 00 0a 0a 07 17 59 0b 07 16 2f e5 06 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_EF_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {61 73 64 61 73 64 61 73 } //2 asdasdas
		$a_81_5 = {4d 6f 6e 65 73 } //2 Mones
		$a_81_6 = {00 62 79 74 65 73 54 6f 42 65 44 65 63 72 79 70 74 65 64 00 } //1 戀瑹獥潔敂敄牣灹整d
		$a_81_7 = {65 78 65 2e 72 74 70 6f 7a 2f 30 36 31 38 36 30 31 37 36 30 32 39 37 34 30 33 31 39 2f 39 31 30 39 31 37 30 31 37 35 36 34 37 34 30 33 31 39 2f 73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 2f 2f 3a 73 70 74 74 68 } //2 exe.rtpoz/061860176029740319/910917017564740319/stnemhcatta/moc.ppadrocsid.ndc//:sptth
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1+(#a_81_7  & 1)*2) >=11
 
}