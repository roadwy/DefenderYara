
rule Ransom_MSIL_FileEncoder_MTB{
	meta:
		description = "Ransom:MSIL/FileEncoder!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 49 56 } //01 00  get_IV
		$a_01_1 = {73 65 74 5f 49 56 } //01 00  set_IV
		$a_01_2 = {47 65 6e 65 72 61 74 65 49 56 } //01 00  GenerateIV
		$a_01_3 = {67 65 74 5f 4d 61 6e 61 67 65 64 54 68 72 65 61 64 49 64 } //01 00  get_ManagedThreadId
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 54 68 72 65 61 64 } //01 00  get_CurrentThread
		$a_01_5 = {44 65 71 75 65 75 65 } //01 00  Dequeue
		$a_01_6 = {45 6e 71 75 65 75 65 } //01 00  Enqueue
		$a_01_7 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //01 00  System.Threading
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_10 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_11 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_12 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_13 = {67 65 74 5f 4b 65 79 } //01 00  get_Key
		$a_01_14 = {73 65 74 5f 4b 65 79 } //01 00  set_Key
		$a_01_15 = {47 65 6e 65 72 61 74 65 4b 65 79 } //01 00  GenerateKey
		$a_01_16 = {2e 00 6b 00 68 00 6f 00 6e 00 73 00 61 00 72 00 69 00 } //00 00  .khonsari
	condition:
		any of ($a_*)
 
}