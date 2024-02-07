
rule Ransom_MSIL_WPlague_DE_MTB{
	meta:
		description = "Ransom:MSIL/WPlague.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_81_0 = {46 72 69 64 61 79 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //05 00  FridayProject.Properties.Resources
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //05 00  DisableTaskMgr
		$a_81_2 = {44 45 43 52 59 50 54 20 46 49 4c 45 53 } //01 00  DECRYPT FILES
		$a_81_3 = {46 72 69 64 61 79 50 72 6f 6a 65 63 74 2e 30 } //01 00  FridayProject.0
		$a_81_4 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } //00 00  Ransomware2.0
	condition:
		any of ($a_*)
 
}