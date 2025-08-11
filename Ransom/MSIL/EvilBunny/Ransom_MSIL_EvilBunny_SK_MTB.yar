
rule Ransom_MSIL_EvilBunny_SK_MTB{
	meta:
		description = "Ransom:MSIL/EvilBunny.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 65 38 61 64 37 35 62 63 2d 61 35 36 66 2d 34 31 39 63 2d 39 34 65 61 2d 64 39 64 33 35 33 32 39 66 37 38 33 } //1 $e8ad75bc-a56f-419c-94ea-d9d35329f783
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 73 70 65 63 69 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 79 74 68 6d } //1 Your files are encrypted with a special encryption algorythm
		$a_81_2 = {45 76 69 6c 42 75 6e 6e 79 5f 52 41 4e 53 4f 4d 57 41 52 45 5c 6f 62 6a 5c 44 65 62 75 67 5c 45 76 69 6c 42 75 6e 6e 79 5f 52 41 4e 53 4f 4d 57 41 52 45 2e 70 64 62 } //1 EvilBunny_RANSOMWARE\obj\Debug\EvilBunny_RANSOMWARE.pdb
		$a_81_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 42 53 4f 44 2e 65 78 65 } //1 C:\Windows\BSOD.exe
		$a_81_4 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 45 76 69 6c 42 75 6e 6e 79 21 } //1 Your files are encrypted by EvilBunny!
		$a_81_5 = {45 76 69 6c 42 75 6e 6e 79 5f 52 41 4e 53 4f 4d 57 41 52 45 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 EvilBunny_RANSOMWARE.Properties.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}