
rule Ransom_MSIL_ZeroLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/ZeroLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {5a 65 72 6f 4c 6f 63 6b 65 72 } //01 00  ZeroLocker
		$a_81_1 = {46 69 6c 65 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 63 72 79 70 74 65 64 21 } //01 00  Files successfully decrypted!
		$a_81_2 = {5a 65 72 6f 4c 6f 63 6b 65 72 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ZeroLocker.Resources
		$a_81_3 = {5a 65 72 6f 4c 6f 63 6b 65 72 20 77 69 6c 6c 20 62 65 20 6e 6f 77 20 72 65 6d 6f 76 65 64 20 66 72 6f 6d 20 79 6f 75 72 20 43 6f 6d 70 75 74 65 72 21 } //00 00  ZeroLocker will be now removed from your Computer!
	condition:
		any of ($a_*)
 
}