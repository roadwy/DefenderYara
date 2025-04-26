
rule Ransom_Win32_Finicrypt_A{
	meta:
		description = "Ransom:Win32/Finicrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 61 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d 2e } //1 have been encrypted using a military grade encryption algorithm.
		$a_01_1 = {41 66 74 65 72 20 32 34 68 20 68 61 76 65 20 70 61 73 73 65 64 2c 20 79 6f 75 72 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 65 72 61 73 65 64 20 61 6e 64 } //1 After 24h have passed, your decryption key will be erased and
		$a_01_2 = {2f 6b 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 /k vssadmin.exe Delete Shadows /All /Quiet
		$a_01_3 = {5c 52 65 61 64 44 65 63 72 79 70 74 46 69 6c 65 73 48 65 72 65 2e 74 78 74 } //1 \ReadDecryptFilesHere.txt
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 43 72 79 70 74 49 6e 66 69 6e 69 74 65 } //1 Software\CryptInfinite
		$a_01_5 = {2e 6f 6e 69 6f 6e 2e 64 69 72 65 63 74 2f 6c 65 6e 64 69 6e 67 2f 62 6f 74 2e 70 68 70 3f 6e 61 6d 65 3d } //1 .onion.direct/lending/bot.php?name=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}