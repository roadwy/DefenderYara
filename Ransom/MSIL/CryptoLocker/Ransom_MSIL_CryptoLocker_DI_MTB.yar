
rule Ransom_MSIL_CryptoLocker_DI_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  your files will be encrypted
		$a_81_1 = {43 72 79 70 74 6f 4c 6f 63 6b 65 72 } //01 00  CryptoLocker
		$a_81_2 = {62 69 63 74 6f 69 6e 73 } //01 00  bictoins
		$a_81_3 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //00 00  /C vssadmin.exe delete shadows /all /quiet
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_CryptoLocker_DI_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0c 00 00 28 00 "
		
	strings :
		$a_81_0 = {2e 41 6e 6e 61 62 65 6c 6c 65 } //28 00  .Annabelle
		$a_81_1 = {2e 62 61 67 6c 69 } //28 00  .bagli
		$a_81_2 = {2e 4c 4f 43 4b 45 44 5f 42 59 5f 57 41 41 4e 4e 41 43 52 59 } //28 00  .LOCKED_BY_WAANNACRY
		$a_81_3 = {54 32 35 35 65 45 78 76 59 32 74 6c 63 69 } //05 00  T255eExvY2tlci
		$a_81_4 = {45 6e 63 72 79 70 74 69 6f 6e 20 46 69 6c 65 73 } //05 00  Encryption Files
		$a_81_5 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 3a } //05 00  Bitcoin address:
		$a_81_6 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //05 00  ExtensionsToEncrypt
		$a_81_7 = {4f 6e 79 78 4c 6f 63 6b 65 72 } //01 00  OnyxLocker
		$a_81_8 = {48 41 43 4b 45 44 } //01 00  HACKED
		$a_81_9 = {45 78 63 65 6c 6c 54 6f 50 64 66 } //01 00  ExcellToPdf
		$a_81_10 = {62 74 63 2e 62 6c 6f 63 6b 72 2e 69 6f } //01 00  btc.blockr.io
		$a_81_11 = {5f 45 6e 63 72 79 70 74 65 64 24 } //00 00  _Encrypted$
	condition:
		any of ($a_*)
 
}