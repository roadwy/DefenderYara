
rule Ransom_MSIL_Teardrop_AA_MTB{
	meta:
		description = "Ransom:MSIL/Teardrop.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 20 4c 6f 76 65 20 46 72 6f 6d 20 56 61 72 30 } //20 All Files Encrypted Love From Var0
		$a_81_1 = {64 69 73 61 62 6c 65 5f 74 61 73 6b 6d 67 72 } //1 disable_taskmgr
		$a_81_2 = {74 65 61 72 64 72 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 teardrop.Properties.Resources
		$a_81_3 = {56 61 72 30 45 78 70 6c 6f 69 74 } //1 Var0Exploit
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=23
 
}