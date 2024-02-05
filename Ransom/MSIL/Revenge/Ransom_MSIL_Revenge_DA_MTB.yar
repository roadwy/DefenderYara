
rule Ransom_MSIL_Revenge_DA_MTB{
	meta:
		description = "Ransom:MSIL/Revenge.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 67 6f 6e 65 } //01 00 
		$a_81_1 = {52 61 6e 73 6f 6d 65 77 61 72 65 } //01 00 
		$a_81_2 = {52 65 61 64 54 6f 52 65 73 74 6f 72 65 2e 74 78 74 } //01 00 
		$a_81_3 = {2e 52 45 56 45 4e 47 45 } //00 00 
	condition:
		any of ($a_*)
 
}