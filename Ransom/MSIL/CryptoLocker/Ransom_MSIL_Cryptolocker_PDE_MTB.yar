
rule Ransom_MSIL_Cryptolocker_PDE_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4b 34 4b 72 61 6e 73 6f 6d } //01 00  K4Kransom
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_81_2 = {46 69 6c 65 45 6e 63 72 79 70 74 } //01 00  FileEncrypt
		$a_81_3 = {45 6e 63 72 79 70 74 65 72 } //01 00  Encrypter
		$a_81_4 = {53 74 61 6c 69 6e } //00 00  Stalin
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDE_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00  ALL YOUR FILES ARE ENCRYPTED
		$a_81_1 = {44 61 72 6b 20 52 61 6e 73 6f 6d 65 77 61 72 65 } //01 00  Dark Ransomeware
		$a_81_2 = {50 6c 65 61 73 65 5f 52 65 61 64 2e 74 78 74 } //01 00  Please_Read.txt
		$a_81_3 = {40 6d 61 69 6c 2e 63 6f 6d } //00 00  @mail.com
	condition:
		any of ($a_*)
 
}