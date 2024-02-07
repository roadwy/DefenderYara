
rule Ransom_MSIL_FileCryptor_V_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 72 79 52 61 6e 73 6f 6d 77 61 72 65 21 } //01 00  Your files have been encrypted by CryRansomware!
		$a_81_1 = {4e 65 76 65 72 20 6f 70 65 6e 20 72 61 6e 64 6f 6d 20 66 69 6c 65 73 2e 20 54 68 69 73 20 69 73 20 79 6f 75 72 20 77 61 72 6e 69 6e 67 } //01 00  Never open random files. This is your warning
		$a_81_2 = {49 73 54 61 72 67 65 74 46 69 6c 65 } //01 00  IsTargetFile
		$a_81_3 = {65 6e 63 54 68 72 65 61 64 } //01 00  encThread
		$a_81_4 = {67 65 74 5f 46 69 6c 65 43 68 65 63 6b 65 72 } //01 00  get_FileChecker
		$a_81_5 = {45 6e 63 72 79 70 74 42 79 74 65 73 } //00 00  EncryptBytes
	condition:
		any of ($a_*)
 
}