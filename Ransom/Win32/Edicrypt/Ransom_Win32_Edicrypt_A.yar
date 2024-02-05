
rule Ransom_Win32_Edicrypt_A{
	meta:
		description = "Ransom:Win32/Edicrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {41 45 53 5f 45 6e 63 72 79 70 74 } //AES_Encrypt  01 00 
		$a_80_1 = {45 6e 63 72 79 70 74 54 65 78 74 } //EncryptText  01 00 
		$a_80_2 = {44 65 63 72 79 70 74 2d 54 6f 6f 6c 20 79 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 21 20 49 66 20 79 6f 75 20 64 6f 6e 27 74 20 70 61 79 } //Decrypt-Tool you can decrypt your files! If you don't pay  01 00 
		$a_80_3 = {4b 65 79 20 74 6f 20 64 65 63 72 79 70 74 3a 20 } //Key to decrypt:   00 00 
	condition:
		any of ($a_*)
 
}