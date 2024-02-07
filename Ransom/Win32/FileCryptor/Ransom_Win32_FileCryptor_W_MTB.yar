
rule Ransom_Win32_FileCryptor_W_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 53 4f 46 54 57 41 52 45 5c 4c 75 63 79 } //01 00  \SOFTWARE\Lucy
		$a_02_1 = {2a 00 2e 00 74 00 78 00 74 00 90 02 2f 2a 00 2e 00 6f 00 64 00 74 00 90 02 2f 2a 00 2e 00 77 00 70 00 73 00 90 00 } //01 00 
		$a_02_2 = {2a 2e 74 78 74 90 02 2f 2a 2e 6f 64 74 90 02 2f 2a 2e 77 70 73 90 00 } //01 00 
		$a_81_3 = {43 72 79 70 74 6f 6c 6f 63 6b 65 72 } //01 00  Cryptolocker
		$a_81_4 = {2e 45 6e 63 6f 64 65 } //01 00  .Encode
		$a_81_5 = {46 69 6c 65 2e 4c 75 73 79 } //01 00  File.Lusy
		$a_81_6 = {44 43 50 63 72 79 70 74 } //01 00  DCPcrypt
		$a_81_7 = {44 43 50 62 61 73 65 36 34 } //00 00  DCPbase64
	condition:
		any of ($a_*)
 
}