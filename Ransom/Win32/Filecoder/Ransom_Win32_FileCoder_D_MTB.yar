
rule Ransom_Win32_FileCoder_D_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 65 20 61 72 65 20 73 6f 20 73 6f 72 72 79 2e 2e 2e 20 59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 We are so sorry... Your files were encrypted!
		$a_81_1 = {2f 63 20 76 53 53 41 64 6d 69 4e 20 64 45 4c 65 54 65 20 53 68 61 44 6f 77 53 20 2f 41 6c 4c 20 2f 71 55 69 65 54 } //1 /c vSSAdmiN dELeTe ShaDowS /AlL /qUieT
		$a_81_2 = {25 66 69 6c 65 69 64 25 2d 44 45 43 52 59 50 54 2e 74 78 74 } //1 %fileid%-DECRYPT.txt
		$a_81_3 = {67 2d 44 45 43 52 59 50 54 2e 74 78 74 } //1 g-DECRYPT.txt
		$a_81_4 = {22 69 70 22 3a 22 25 69 70 25 22 2c 22 63 6f 75 6e 74 72 79 22 3a 22 25 63 6e 74 25 22 2c 22 76 65 72 73 69 6f 6e 22 3a 22 25 76 65 72 25 22 2c 22 63 6f 6d 70 75 74 65 72 5f 6e 61 6d 65 22 3a 22 25 63 6f 6d 70 6e 61 6d 65 25 22 2c 22 75 73 65 72 6e 61 6d 65 22 3a 22 25 75 73 65 72 25 22 2c 22 6f 73 22 3a 22 25 77 69 6e 25 22 2c 22 70 72 5f 6b 65 79 22 3a } //1 "ip":"%ip%","country":"%cnt%","version":"%ver%","computer_name":"%compname%","username":"%user%","os":"%win%","pr_key":
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}
rule Ransom_Win32_FileCoder_D_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.D!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 65 77 61 72 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Ransomeware.My.Resources
		$a_01_1 = {42 69 74 63 6f 69 6e 73 } //1 Bitcoins
		$a_01_2 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 Decryption Key
		$a_01_3 = {6c 00 6f 00 61 00 64 00 65 00 72 00 2d 00 67 00 69 00 66 00 2d 00 33 00 30 00 30 00 2d 00 73 00 70 00 69 00 6e 00 6e 00 65 00 72 00 2d 00 } //1 loader-gif-300-spinner-
		$a_01_4 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 } //1 /C choice /C Y /N /D Y /T
		$a_01_5 = {52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62 } //1 Ransomeware.pdb
		$a_01_6 = {4c 00 4f 00 53 00 54 00 20 00 61 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //1 LOST all your files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}