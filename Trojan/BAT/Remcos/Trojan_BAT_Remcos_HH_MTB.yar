
rule Trojan_BAT_Remcos_HH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2f 73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 2f 2f 3a 73 70 74 74 68 } //1 /stnemhcatta/moc.ppadrocsid.ndc//:sptth
		$a_81_1 = {42 49 47 42 4f 53 53 } //1 BIGBOSS
		$a_81_2 = {66 64 67 66 64 65 77 65 77 } //1 fdgfdewew
		$a_81_3 = {73 61 64 73 61 64 61 73 } //1 sadsadas
		$a_81_4 = {64 73 66 64 73 66 } //1 dsfdsf
		$a_81_5 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_7 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}