
rule Ransom_Win32_KKKryptoLocker_A_rsm{
	meta:
		description = "Ransom:Win32/KKKryptoLocker.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 "
		
	strings :
		$a_01_0 = {4b 00 4b 00 4b 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 } //100 KKKryptoLocker
		$a_01_1 = {4f 00 6f 00 6f 00 70 00 73 00 2c 00 20 00 73 00 70 00 6f 00 6e 00 67 00 65 00 62 00 6f 00 62 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 21 00 } //100 Ooops, spongebob is encrypting your files!
		$a_01_2 = {53 00 50 00 4f 00 4e 00 47 00 45 00 42 00 4f 00 42 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 20 00 32 00 2e 00 30 00 } //100 SPONGEBOB RANSOMWARE 2.0
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 4a 61 72 65 64 5c 44 65 73 6b 74 6f 70 5c 72 61 6e 73 6f 6d 77 61 72 65 5c 4b 4b 4b 72 79 70 74 6f 4c 6f 63 6b 65 72 5c 4b 4b 4b 72 79 70 74 6f 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 4b 4b 72 79 70 74 6f 4c 6f 63 6b 65 72 2e 70 64 62 } //100 C:\Users\Jared\Desktop\ransomware\KKKryptoLocker\KKKryptoLocker\obj\Debug\KKKryptoLocker.pdb
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100) >=400
 
}