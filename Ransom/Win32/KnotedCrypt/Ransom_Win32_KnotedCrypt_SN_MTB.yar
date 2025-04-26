
rule Ransom_Win32_KnotedCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/KnotedCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 6c 00 73 00 2d 00 48 00 45 00 4c 00 50 00 2e 00 74 00 78 00 74 00 } //1 %ls-HELP.txt
		$a_01_1 = {54 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 61 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 79 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 74 00 6f 00 20 00 62 00 75 00 79 00 20 00 6f 00 75 00 72 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 3a 00 20 00 4b 00 6e 00 6f 00 74 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 To decrypt all your files you have to buy our software: KnotDecryptor
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c } //1 vssadmin.exe Delete Shadows /All
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}