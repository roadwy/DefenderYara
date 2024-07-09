
rule Ransom_Win32_Sarento_A{
	meta:
		description = "Ransom:Win32/Sarento.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {25 73 76 69 63 74 3f 63 75 73 74 3d 25 73 26 67 75 69 64 3d 25 73 } //%svict?cust=%s&guid=%s  2
		$a_80_1 = {2e 74 6f 2f 76 69 63 74 3f 63 75 73 74 3d } //.to/vict?cust=  1
		$a_80_2 = {65 6e 63 72 79 70 74 6f 72 5f 72 61 61 73 5f 72 65 61 64 6d 65 5f 6c 69 65 73 6d 69 63 68 2e 74 78 74 } //encryptor_raas_readme_liesmich.txt  2
		$a_80_3 = {54 68 65 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 73 65 63 75 72 65 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 45 6e 63 72 79 70 74 6f 72 20 52 61 61 53 2e } //The files on your computer have been securely encrypted by Encryptor RaaS.  2
		$a_80_4 = {77 61 6c 6c 65 74 2e 64 61 74 } //wallet.dat  1
		$a_80_5 = {45 6e 63 72 79 70 74 6f 72 20 52 61 61 53 } //Encryptor RaaS  1
		$a_03_6 = {81 7c 24 18 3e 1d 60 a2 75 ?? 81 7c 24 1c 17 cc 49 c1 75 } //2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_03_6  & 1)*2) >=5
 
}