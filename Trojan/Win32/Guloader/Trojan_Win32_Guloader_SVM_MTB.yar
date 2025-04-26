
rule Trojan_Win32_Guloader_SVM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_81_0 = {71 75 61 64 72 69 63 69 6c 69 61 74 65 2e 74 78 74 } //2 quadriciliate.txt
		$a_81_1 = {62 75 64 67 65 72 65 65 67 61 68 2e 6a 70 67 } //2 budgereegah.jpg
		$a_81_2 = {61 76 69 73 73 6b 72 69 76 65 72 69 65 72 2e 6a 70 67 } //2 avisskriverier.jpg
		$a_81_3 = {54 65 6b 73 74 6d 61 73 73 65 73 32 32 37 2e 69 6e 69 } //2 Tekstmasses227.ini
		$a_81_4 = {52 65 74 72 6f 70 6f 73 65 64 2e 6a 70 67 } //2 Retroposed.jpg
		$a_81_5 = {44 65 6c 62 65 74 61 6c 69 6e 67 65 72 73 2e 74 78 74 } //2 Delbetalingers.txt
		$a_81_6 = {63 6f 6e 74 72 61 63 74 69 62 6c 65 6e 65 73 73 5c 62 72 65 62 6c 67 65 72 6e 65 73 } //2 contractibleness\breblgernes
		$a_81_7 = {73 6b 72 75 65 74 72 6b 6b 65 72 65 73 2e 6d 75 73 } //1 skruetrkkeres.mus
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*1) >=15
 
}