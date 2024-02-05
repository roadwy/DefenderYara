
rule Ransom_AndroidOS_Congur_B_MTB{
	meta:
		description = "Ransom:AndroidOS/Congur.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 75 6c 61 6e 67 2f 63 6c 6f 63 6b 2f 42 6f 6f 74 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //02 00 
		$a_01_1 = {43 6c 6f 63 6b 53 65 72 76 69 63 65 } //01 00 
		$a_01_2 = {76 61 6c 24 70 73 77 } //01 00 
		$a_01_3 = {73 65 74 4f 6e 43 6c 69 63 6b 4c 69 73 74 65 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}