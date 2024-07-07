
rule Trojan_BAT_WarzoneRat_DF_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 63 30 35 35 63 30 64 66 2d 30 65 39 61 2d 34 35 37 66 2d 61 35 39 36 2d 30 38 36 37 37 34 66 33 39 30 66 62 } //1 $c055c0df-0e9a-457f-a596-086774f390fb
		$a_81_1 = {48 61 70 6c 6f 54 72 65 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 HaploTree.My.Resources
		$a_81_2 = {48 61 70 6c 6f 54 72 65 65 2e 45 6e 74 65 72 70 69 73 65 } //1 HaploTree.Enterpise
		$a_81_3 = {73 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 set_ConnectionString
		$a_81_4 = {72 65 6d 6f 76 65 5f 4d 6f 75 73 65 44 6f 75 62 6c 65 43 6c 69 63 6b } //1 remove_MouseDoubleClick
		$a_81_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_6 = {4d 79 54 65 73 74 2e 74 78 74 } //1 MyTest.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}