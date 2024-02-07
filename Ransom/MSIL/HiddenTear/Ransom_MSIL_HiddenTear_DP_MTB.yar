
rule Ransom_MSIL_HiddenTear_DP_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 69 64 64 65 6e 5f 74 65 61 72 32 2e 65 78 65 } //01 00  hidden_tear2.exe
		$a_81_1 = {68 69 64 64 65 6e 5f 74 65 61 72 32 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  hidden_tear2.Properties
		$a_81_2 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  GetDirectories
		$a_81_3 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //01 00  GetExtension
		$a_81_4 = {47 65 74 46 69 6c 65 73 } //00 00  GetFiles
	condition:
		any of ($a_*)
 
}