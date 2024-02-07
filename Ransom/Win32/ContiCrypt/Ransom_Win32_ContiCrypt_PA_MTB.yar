
rule Ransom_Win32_ContiCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 63 6f 6e 74 69 5f 76 33 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 63 72 79 70 74 6f 72 5f 64 6c 6c 2e 70 64 62 } //01 00  \conti_v3\x64\Release\cryptor_dll.pdb
		$a_01_1 = {61 6c 6c 20 6f 66 20 74 68 65 20 64 61 74 61 20 74 68 61 74 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 6f 75 72 20 73 6f 66 74 77 61 72 65 20 63 61 6e 6e 6f 74 20 62 65 20 72 65 63 6f 76 65 72 65 } //01 00  all of the data that has been encrypted by our software cannot be recovere
		$a_01_2 = {79 6f 75 20 74 6f 20 64 65 63 72 79 70 74 20 32 20 72 61 6e 64 6f 6d 20 66 69 6c 65 73 20 63 6f 6d 70 6c 65 74 65 6c 79 20 66 72 65 65 20 6f 66 20 63 68 61 72 67 65 } //01 00  you to decrypt 2 random files completely free of charge
		$a_01_3 = {2e 00 50 00 4b 00 56 00 44 00 54 00 } //00 00  .PKVDT
	condition:
		any of ($a_*)
 
}