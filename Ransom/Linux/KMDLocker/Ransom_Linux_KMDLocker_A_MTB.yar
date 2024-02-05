
rule Ransom_Linux_KMDLocker_A_MTB{
	meta:
		description = "Ransom:Linux/KMDLocker.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 2e 66 75 6e 63 } //01 00 
		$a_01_1 = {6d 61 69 6e 2e 63 72 65 61 74 65 5f 6d 65 73 73 61 67 65 } //01 00 
		$a_01_2 = {2f 6f 70 74 2f 61 67 65 6c 6f 63 6b 65 72 2f 61 67 65 6c 6f 63 6b 65 72 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}