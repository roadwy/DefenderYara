
rule Ransom_MSIL_WannaCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/WannaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 61 00 65 00 73 00 } //01 00  .aes
		$a_01_1 = {5c 00 62 00 67 00 2e 00 70 00 6e 00 67 00 } //01 00  \bg.png
		$a_01_2 = {5c 00 52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //01 00  \Readme.txt
		$a_01_3 = {5c 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 4b 00 65 00 79 00 2e 00 74 00 78 00 74 00 } //01 00  \EncryptedKey.txt
		$a_01_4 = {59 00 6f 00 75 00 72 00 20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  Your important files are encrypted
	condition:
		any of ($a_*)
 
}