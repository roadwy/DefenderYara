
rule Ransom_MSIL_NoCry_MK_MTB{
	meta:
		description = "Ransom:MSIL/NoCry.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2f 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 } //0a 00  All Your Files Are Encrypted
		$a_81_1 = {59 65 73 2c 20 59 6f 75 20 43 61 6e 20 52 65 63 6f 76 65 72 20 41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 45 61 73 69 6c 79 20 41 6e 64 20 51 75 69 63 6b 6c 79 } //0a 00  Yes, You Can Recover All Your Files Easily And Quickly
		$a_81_2 = {49 20 57 69 6c 6c 20 53 65 6e 64 20 54 68 65 20 4b 65 79 20 54 6f 20 59 6f 75 20 46 6f 72 20 44 65 63 72 79 70 74 69 6f 6e } //05 00  I Will Send The Key To You For Decryption
		$a_81_3 = {4e 6f 43 72 79 20 44 65 63 72 79 70 74 6f 72 } //01 00  NoCry Decryptor
		$a_81_4 = {43 72 79 2e 69 6d 67 } //0a 00  Cry.img
		$a_81_5 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 2e 68 74 6d 6c } //01 00  How To Decrypt My Files.html
		$a_81_6 = {40 79 61 6e 64 65 78 2e 63 6f 6d } //00 00  @yandex.com
		$a_00_7 = {5d 04 00 00 a3 6c 04 80 5c 26 00 00 a4 6c 04 80 00 00 01 00 08 00 10 00 ac 21 51 73 68 65 6c 6c 2e 47 4b 4d 21 4d 54 42 } //00 00 
	condition:
		any of ($a_*)
 
}