
rule Ransom_MSIL_Cryptolocker_PDI_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All Files on your system has been encrypted
		$a_81_1 = {68 6f 77 5f 74 6f 5f 72 65 63 6f 76 65 72 } //01 00  how_to_recover
		$a_81_2 = {68 69 64 64 65 6e 20 74 65 61 72 } //01 00  hidden tear
		$a_81_3 = {2e 48 41 4e 54 41 } //00 00  .HANTA
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDI_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 69 6e 64 6f 77 73 20 53 74 6f 72 65 20 44 6f 77 6e 6c 6f 61 64 } //01 00  Windows Store Download
		$a_81_1 = {2e 6c 6f 63 6b 65 64 } //01 00  .locked
		$a_81_2 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //01 00  EncryptString
		$a_81_3 = {46 69 6c 65 45 78 74 65 6e 73 69 6f 6e } //01 00  FileExtension
		$a_81_4 = {45 6e 63 72 79 70 74 41 45 53 } //01 00  EncryptAES
		$a_81_5 = {45 6e 63 72 79 70 74 4b 65 79 } //01 00  EncryptKey
		$a_81_6 = {52 53 41 4b 65 79 2e 74 78 74 } //00 00  RSAKey.txt
	condition:
		any of ($a_*)
 
}