
rule Trojan_Win64_CryptInject_XY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6c 66 73 5f 65 6f 70 2e 70 64 62 } //01 00  clfs_eop.pdb
		$a_01_1 = {43 41 46 45 43 41 46 45 } //01 00  CAFECAFE
		$a_01_2 = {6e 75 6d 62 65 72 20 6f 66 20 70 69 70 65 73 20 63 72 65 61 74 65 64 } //00 00  number of pipes created
	condition:
		any of ($a_*)
 
}