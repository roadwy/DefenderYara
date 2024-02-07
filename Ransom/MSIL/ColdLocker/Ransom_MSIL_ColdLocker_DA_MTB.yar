
rule Ransom_MSIL_ColdLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/ColdLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6f 6c 64 4c 6f 63 6b 65 72 } //01 00  ColdLocker
		$a_81_1 = {48 6f 77 20 54 6f 20 55 6e 6c 6f 63 6b 20 46 69 6c 65 73 2e 74 78 74 } //01 00  How To Unlock Files.txt
		$a_81_2 = {72 65 61 64 6d 65 2e 74 6d 70 } //01 00  readme.tmp
		$a_81_3 = {5c 43 6f 6c 64 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6f 6c 64 4c 6f 63 6b 65 72 2e 70 64 62 } //00 00  \ColdLocker\obj\Release\ColdLocker.pdb
	condition:
		any of ($a_*)
 
}