
rule Trojan_BAT_Bladabindi_EV_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {54 65 73 74 43 72 79 70 74 65 72 } //3 TestCrypter
		$a_81_1 = {64 33 63 72 34 70 74 } //3 d3cr4pt
		$a_81_2 = {64 63 72 70 } //3 dcrp
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //3 DownloadFile
		$a_81_4 = {63 72 34 70 74 33 64 } //3 cr4pt3d
		$a_81_5 = {44 65 62 75 67 5c 54 65 73 74 43 72 79 70 74 65 72 30 2e 70 64 62 } //3 Debug\TestCrypter0.pdb
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //3 FromBase64String
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}