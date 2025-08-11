
rule Ransom_Win64_Inc_BAA_MTB{
	meta:
		description = "Ransom:Win64/Inc.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5b 49 4e 43 2d 52 45 41 44 4d 45 2e 74 78 74 2e 2e 77 69 6e 64 6f 77 73 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 61 70 70 64 61 74 61 } //1 [INC-README.txt..windowsprogram filesappdata
		$a_81_1 = {24 72 65 63 79 63 6c 65 2e 62 69 6e 70 72 6f 67 72 61 6d 64 61 74 61 61 6c 6c 20 75 73 65 72 73 73 6f 70 68 6f 73 49 4e 43 2e 6c 6f 67 2e 64 6c 6c 2e 65 78 65 } //1 $recycle.binprogramdataall userssophosINC.log.dll.exe
		$a_81_2 = {77 68 69 6c 65 20 64 65 6c 65 74 69 6e 67 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 66 72 6f 6d } //1 while deleting shadow copies from
		$a_81_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 6c 65 74 65 64 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 66 72 6f 6d 20 40 64 } //1 Successfully deleted shadow copies from @d
		$a_81_4 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 65 73 20 62 79 20 6d 61 73 6b } //1 Successfully killed processes by mask
		$a_81_5 = {77 68 69 6c 65 20 65 6e 63 72 79 70 74 69 6e 67 20 66 69 6c 65 } //1 while encrypting file
		$a_81_6 = {45 6e 63 72 79 70 74 69 6f 6e 41 6c 67 6f 53 41 4c 53 41 32 30 41 45 53 45 6e 63 72 79 70 74 69 6f 6e 48 65 61 64 65 72 } //1 EncryptionAlgoSALSA20AESEncryptionHeader
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}