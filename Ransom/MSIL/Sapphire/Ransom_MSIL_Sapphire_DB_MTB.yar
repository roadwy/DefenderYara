
rule Ransom_MSIL_Sapphire_DB_MTB{
	meta:
		description = "Ransom:MSIL/Sapphire.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 61 70 70 68 69 72 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Sapphire Ransomware
		$a_81_1 = {2e 73 61 70 70 68 69 72 65 } //01 00  .sapphire
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_3 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //00 00  Encryption Complete
	condition:
		any of ($a_*)
 
}