
rule Ransom_Win32_Critroni_B_{
	meta:
		description = "Ransom:Win32/Critroni.B!!Critroni.gen,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {25 66 31 25 25 63 31 25 25 6b 65 79 25 25 66 30 25 25 63 30 25 } //1 %f1%%c1%%key%%f0%%c0%
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 2e 25 66 30 25 25 63 30 25 } //1 encrypted.%f0%%c0%
		$a_01_2 = {25 61 31 25 25 66 33 25 25 63 33 25 54 65 73 74 20 64 65 63 72 79 70 74 69 6f 6e 2e 25 66 30 25 25 63 30 25 } //1 %a1%%f3%%c3%Test decryption.%f0%%c0%
		$a_01_3 = {25 61 31 25 25 66 33 25 25 63 33 25 52 65 71 75 65 73 74 69 6e 67 20 70 72 69 76 61 74 65 20 6b 65 79 2e 25 66 30 25 25 63 30 25 } //1 %a1%%f3%%c3%Requesting private key.%f0%%c0%
		$a_01_4 = {41 00 6c 00 6c 00 46 00 69 00 6c 00 65 00 73 00 41 00 72 00 65 00 4c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 AllFilesAreLocked
		$a_01_5 = {63 00 74 00 62 00 32 00 } //1 ctb2
		$a_03_6 = {6b 65 79 3d [0-08] 75 73 64 3d [0-0c] 61 64 64 72 65 73 73 3d 00 } //1
		$a_03_7 = {62 74 63 70 72 69 63 65 [0-08] 75 73 64 70 72 69 63 65 } //1
		$a_01_8 = {50 4f 53 54 20 2f 75 6e 6c 6f 63 6b 20 48 54 54 50 2f 31 2e 31 } //1 POST /unlock HTTP/1.1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}