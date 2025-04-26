
rule Trojan_BAT_Remcos_GG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {74 68 65 64 65 76 69 6c 63 6f 64 65 72 } //1 thedevilcoder
		$a_81_1 = {6c 61 78 79 6d 61 6e 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //1 laxyman.000webhostapp.com
		$a_81_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //1 WindowsFormsApp
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}