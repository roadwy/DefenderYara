
rule Ransom_Win64_NitrogenCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/NitrogenCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 69 74 72 6f 67 65 6e 20 77 65 6c 63 6f 6d 65 20 79 6f 75 21 } //5 Nitrogen welcome you!
		$a_01_1 = {5f 52 45 41 44 5f 4d 45 5f 2e 54 58 54 } //1 _READ_ME_.TXT
		$a_01_2 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //2 /c vssadmin.exe delete shadows /all /quiet
		$a_01_3 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 readme.txt
		$a_01_4 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 20 00 25 00 6c 00 73 00 20 00 2f 00 66 00 } //1 cmd /c taskkill /im %ls /f
		$a_01_5 = {62 63 64 65 64 69 74 20 2f 64 65 6c 65 74 65 76 61 6c 75 65 20 7b 64 65 66 61 75 6c 74 7d 20 73 61 66 65 62 6f 6f 74 } //1 bcdedit /deletevalue {default} safeboot
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}