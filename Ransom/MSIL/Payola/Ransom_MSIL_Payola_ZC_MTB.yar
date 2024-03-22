
rule Ransom_MSIL_Payola_ZC_MTB{
	meta:
		description = "Ransom:MSIL/Payola.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 20 00 69 00 6e 00 20 00 7b 00 30 00 7d 00 20 00 6d 00 73 00 } //01 00  Encryption Completed in {0} ms
		$a_01_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 44 00 72 00 69 00 76 00 65 00 3a 00 } //01 00  Encrypting Drive:
		$a_01_2 = {44 00 65 00 6c 00 65 00 74 00 65 00 64 00 20 00 42 00 61 00 63 00 6b 00 75 00 70 00 73 00 20 00 26 00 20 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 20 00 43 00 6f 00 70 00 69 00 65 00 73 00 } //01 00  Deleted Backups & Volume Shadow Copies
		$a_01_3 = {50 61 79 6f 6c 61 2e 70 64 62 } //01 00  Payola.pdb
		$a_81_4 = {59 6f 75 72 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 50 61 79 6f 6c 61 } //01 00  Your data was encrypted by Payola
		$a_01_5 = {4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 68 00 6f 00 6e 00 65 00 79 00 40 00 70 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 70 00 73 00 74 00 } //01 00  Outlook Files\honey@pot.com.pst
		$a_01_6 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 50 00 61 00 74 00 68 00 3a 00 } //01 00  Encrypted Path:
		$a_01_7 = {50 00 61 00 79 00 6f 00 6c 00 61 00 20 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //01 00  Payola Locker
		$a_01_8 = {6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 45 00 52 00 41 00 57 00 54 00 46 00 4f 00 53 00 } //00 00  nuR\noisreVtnerruC\swodniW\tfosorciM\ERAWTFOS
	condition:
		any of ($a_*)
 
}