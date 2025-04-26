
rule Trojan_BAT_PandoraBlade_ASG_MSR{
	meta:
		description = "Trojan:BAT/PandoraBlade.ASG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,7a 00 78 00 09 00 00 "
		
	strings :
		$a_80_0 = {73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 } //stnemhcatta/moc.ppadrocsid.ndc  100
		$a_02_1 = {62 00 69 00 6e 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 53 00 4c 00 4e 00 [0-30] 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 [0-30] 2e 00 70 00 64 00 62 00 } //2
		$a_02_2 = {62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e [0-30] 6f 62 6a 5c 44 65 62 75 67 [0-30] 2e 70 64 62 } //2
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  5
		$a_80_4 = {49 6e 76 6f 6b 65 } //Invoke  5
		$a_80_5 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  5
		$a_80_6 = {53 79 73 74 65 6d 2e 4e 65 74 } //System.Net  5
		$a_80_7 = {4c 6f 67 69 6e } //Login  1
		$a_80_8 = {50 61 73 73 77 6f 72 64 } //Password  1
	condition:
		((#a_80_0  & 1)*100+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=120
 
}