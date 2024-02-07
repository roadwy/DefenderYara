
rule Ransom_MSIL_PoC_DA_MTB{
	meta:
		description = "Ransom:MSIL/PoC.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 6f 43 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  PoC Ransomware
		$a_81_1 = {45 6e 63 72 79 70 74 44 69 72 } //01 00  EncryptDir
		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00  EncryptFile
		$a_81_3 = {67 65 74 5f 45 78 74 65 6e 73 69 6f 6e } //00 00  get_Extension
	condition:
		any of ($a_*)
 
}