
rule Trojan_BAT_Formbook_RPB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 00 2e 00 75 00 67 00 75 00 75 00 2e 00 73 00 65 00 } //1 i.uguu.se
		$a_01_1 = {57 00 66 00 79 00 5a 00 76 00 58 00 51 00 62 00 2e 00 72 00 74 00 66 00 } //1 WfyZvXQb.rtf
		$a_01_2 = {66 00 69 00 78 00 65 00 64 00 68 00 6f 00 73 00 74 00 2e 00 6d 00 6f 00 64 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 fixedhost.modulation
		$a_01_3 = {74 00 72 00 61 00 64 00 69 00 6e 00 67 00 } //1 trading
		$a_01_4 = {42 61 6e 67 76 34 2e 70 64 62 } //1 Bangv4.pdb
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}