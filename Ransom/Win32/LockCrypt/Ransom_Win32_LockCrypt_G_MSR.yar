
rule Ransom_Win32_LockCrypt_G_MSR{
	meta:
		description = "Ransom:Win32/LockCrypt.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 65 6e 74 69 6f 6e 21 21 21 20 59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 21 21 21 } //1 Attention!!! Your files are encrypted !!!
		$a_01_1 = {54 6f 20 72 65 63 6f 76 65 72 20 66 69 6c 65 73 2c 20 66 6f 6c 6c 6f 77 20 74 68 65 20 70 72 6f 6d 70 74 73 20 69 6e 20 74 68 65 20 74 65 78 74 20 66 69 6c 65 20 22 52 65 61 64 6d 65 22 } //1 To recover files, follow the prompts in the text file "Readme"
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //1 vssadmin delete shadows /all
		$a_01_3 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //1 MPGoodStatus
		$a_01_4 = {64 6f 77 6e 6c 6f 61 64 20 6b 65 79 20 6f 6b } //1 download key ok
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}