
rule Ransom_MSIL_FileCryptor_PA_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //01 00  fileEncrypted
		$a_01_1 = {4f 46 46 5f 45 6e 63 72 79 70 74 } //01 00  OFF_Encrypt
		$a_01_2 = {69 00 6d 00 67 00 5f 00 35 00 36 00 36 00 39 00 34 00 } //01 00  img_56694
		$a_01_3 = {55 00 4e 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 } //01 00  UNLOCKED
		$a_01_4 = {5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 } //01 00  \desktop.ini
		$a_01_5 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 32 00 2e 00 30 00 } //0a 00  Ransomware2.0
		$a_03_6 = {5c 52 61 6e 73 6f 6d 77 61 72 65 90 02 06 5c 90 02 10 5c 90 02 10 5c 52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 2e 70 64 62 90 00 } //0a 00 
		$a_03_7 = {5c 52 61 73 6f 6d 77 61 72 65 90 02 06 5c 90 02 10 5c 90 02 10 5c 52 61 73 6f 6d 77 61 72 65 32 2e 30 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}