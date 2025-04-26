
rule Ransom_Win32_FileCoder_A_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6f 20 6e 6f 74 20 73 68 75 74 64 6f 77 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6f 72 20 74 72 79 20 74 6f 20 63 6c 6f 73 65 20 74 68 69 73 20 70 72 6f 67 72 61 6d 3a 20 41 6c 6c 20 79 6f 75 72 20 70 65 72 73 6f 6e 6e 61 6c 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 21 } //1 Do not shutdown your computer or try to close this program: All your personnal data will be deleted !
		$a_81_1 = {34 39 48 38 4b 62 66 31 35 4a 46 4e 32 64 69 47 35 65 76 47 48 41 35 47 34 39 71 68 67 46 42 75 44 69 64 38 36 7a 33 4d 4b 78 54 76 35 39 64 63 71 79 53 43 7a 46 57 55 4c 33 53 67 73 45 6b 32 53 75 66 7a 54 7a 69 48 70 33 55 45 35 50 38 42 61 74 77 75 79 46 75 76 31 62 42 4b 51 77 32 } //1 49H8Kbf15JFN2diG5evGHA5G49qhgFBuDid86z3MKxTv59dcqySCzFWUL3SgsEk2SufzTziHp3UE5P8BatwuyFuv1bBKQw2
		$a_01_2 = {4d 6f 73 74 20 6f 66 20 79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 41 45 53 20 32 35 36 } //1 Most of your data has been encrypted by AES 256
		$a_01_3 = {73 65 6e 64 20 75 73 20 24 20 33 30 30 20 69 6e 20 4d 6f 6e 65 72 6f 20 73 65 6e 74 20 74 6f 20 74 68 65 20 61 64 64 72 65 73 73 20 79 6f 75 20 63 61 6e 20 73 65 65 20 62 65 6c 6f 77 } //1 send us $ 300 in Monero sent to the address you can see below
		$a_01_4 = {59 6f 75 20 63 61 6e 20 67 65 74 20 6d 6f 6e 65 72 6f 20 68 65 72 65 20 3a 20 68 74 74 70 73 3a 2f 2f 6c 6f 63 61 6c 6d 6f 6e 65 72 6f 2e 63 6f 2f } //1 You can get monero here : https://localmonero.co/
		$a_01_5 = {5c 47 47 2d 52 61 6e 73 6f 6d 77 61 72 65 2d 6d 61 73 74 65 72 5c 47 47 20 72 61 6e 73 6f 6d 77 61 72 65 5c 47 47 20 72 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 2e 70 64 62 } //1 \GG-Ransomware-master\GG ransomware\GG ransomware\obj\Debug\Ransom.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}