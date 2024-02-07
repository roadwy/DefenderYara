
rule Ransom_Win32_AmigUCrypt_MTB{
	meta:
		description = "Ransom:Win32/AmigUCrypt!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 41 00 6d 00 69 00 67 00 6f 00 2d 00 55 00 32 00 } //01 00  .Amigo-U2
		$a_00_1 = {21 00 21 00 21 00 52 00 45 00 41 00 44 00 5f 00 49 00 54 00 21 00 21 00 21 00 2e 00 74 00 78 00 74 00 } //01 00  !!!READ_IT!!!.txt
		$a_00_2 = {41 00 4c 00 4c 00 20 00 59 00 4f 00 55 00 52 00 20 00 44 00 41 00 54 00 41 00 20 00 57 00 41 00 53 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //01 00  ALL YOUR DATA WAS ENCRYPTED
		$a_01_3 = {45 6e 63 72 79 70 74 6f 72 2e 65 78 65 } //01 00  Encryptor.exe
		$a_01_4 = {3c 43 72 65 61 74 65 43 72 79 70 74 65 72 3e } //01 00  <CreateCrypter>
		$a_01_5 = {3c 45 6e 63 72 79 70 74 46 69 6c 65 3e } //00 00  <EncryptFile>
	condition:
		any of ($a_*)
 
}