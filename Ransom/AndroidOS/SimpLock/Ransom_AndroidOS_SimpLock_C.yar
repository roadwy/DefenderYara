
rule Ransom_AndroidOS_SimpLock_C{
	meta:
		description = "Ransom:AndroidOS/SimpLock.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 65 62 75 68 61 34 61 2e 6e 65 74 2f 6b 65 79 73 2f } //01 00 
		$a_01_1 = {4c 61 6e 64 72 6f 69 64 2f 6f 73 2f 50 6f 77 65 72 4d 61 6e 61 67 65 72 24 57 61 6b 65 4c 6f 63 6b 3b } //01 00 
		$a_01_2 = {67 65 6e 6b 65 79 } //01 00 
		$a_01_3 = {57 61 6b 65 66 75 6c 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 2e 6a 61 76 61 } //00 00 
	condition:
		any of ($a_*)
 
}