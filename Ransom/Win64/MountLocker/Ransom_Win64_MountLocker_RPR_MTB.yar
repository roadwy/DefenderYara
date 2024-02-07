
rule Ransom_Win64_MountLocker_RPR_MTB{
	meta:
		description = "Ransom:Win64/MountLocker.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 75 61 6e 74 75 6d 20 4c 6f 63 6b 65 72 } //01 00  Quantum Locker
		$a_01_1 = {2e 6f 6e 69 6f 6e } //01 00  .onion
		$a_01_2 = {52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 54 00 4f 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 } //01 00  README_TO_DECRYPT
		$a_01_3 = {6c 6f 63 6b 65 72 5f 36 34 } //01 00  locker_64
		$a_01_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //00 00  CryptEncrypt
	condition:
		any of ($a_*)
 
}