
rule Ransom_MSIL_CryptJoke_A_bit{
	meta:
		description = "Ransom:MSIL/CryptJoke.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 46 69 6c 65 43 72 79 70 74 65 72 4a 6f 6b 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 69 6c 65 43 72 79 70 74 65 72 4a 6f 6b 65 2e 70 64 62 } //01 00  \FileCrypterJoke\obj\Debug\FileCrypterJoke.pdb
		$a_01_1 = {49 6e 69 74 69 61 6c 69 7a 65 52 61 6e 64 6f 6d 58 6f 72 4b 65 79 } //01 00  InitializeRandomXorKey
		$a_01_2 = {43 72 79 70 74 41 6c 6c 46 69 6c 65 73 49 6e 46 6f 6c 64 65 72 } //01 00  CryptAllFilesInFolder
		$a_01_3 = {2a 00 2e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  *.crypted
	condition:
		any of ($a_*)
 
}