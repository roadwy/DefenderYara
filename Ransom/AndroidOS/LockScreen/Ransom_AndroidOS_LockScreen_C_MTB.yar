
rule Ransom_AndroidOS_LockScreen_C_MTB{
	meta:
		description = "Ransom:AndroidOS/LockScreen.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6c 6f 6c 6f 6c 70 2e 4c 6f 63 6b 53 65 72 76 69 63 65 00 } //01 00 
		$a_00_1 = {40 69 e2 80 8c 72 68 e2 80 8c 61 63 6b 5f 61 70 e2 80 8c 70 } //01 00 
		$a_00_2 = {6d 61 6d 61 64 31 37 6d } //01 00 
		$a_00_3 = {67 65 74 53 79 73 74 65 6d 53 65 72 76 69 63 65 28 22 6c 61 79 6f 75 74 5f 69 6e 66 6c 61 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}