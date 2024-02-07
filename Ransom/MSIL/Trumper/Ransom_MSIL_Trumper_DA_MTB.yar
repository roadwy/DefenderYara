
rule Ransom_MSIL_Trumper_DA_MTB{
	meta:
		description = "Ransom:MSIL/Trumper.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 65 6e 64 20 30 2e 30 31 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 61 64 64 72 65 73 73 3a } //01 00  Send 0.01 Bitcoin to the following address:
		$a_81_1 = {44 45 43 52 59 50 54 49 4f 4e 20 4b 45 59 20 44 45 4c 45 54 45 44 20 4f 4e 3a } //01 00  DECRYPTION KEY DELETED ON:
		$a_81_2 = {5f 54 72 69 6e 69 74 79 5f 4f 62 66 75 73 63 61 74 6f 72 5f } //01 00  _Trinity_Obfuscator_
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 20 59 61 48 65 69 } //01 00  Microsoft YaHei
		$a_81_4 = {43 68 72 6f 6d 69 6f } //01 00  Chromio
		$a_81_5 = {55 48 20 4f 48 21 } //00 00  UH OH!
	condition:
		any of ($a_*)
 
}