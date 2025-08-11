
rule Ransom_Win32_DurrCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/DurrCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 55 49 43 6c 61 73 73 } //1 RansomwareUIClass
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 44 75 72 72 2e 6c 6f 63 6b } //1 C:\ProgramData\Durr.lock
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //1 schtasks /create /tn
		$a_01_3 = {44 00 2e 00 55 00 2e 00 52 00 2e 00 52 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 } //4 D.U.R.R Ransom
		$a_01_4 = {59 00 6f 00 75 00 72 00 20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 75 00 73 00 69 00 6e 00 67 00 20 00 6d 00 69 00 6c 00 69 00 74 00 61 00 72 00 79 00 20 00 67 00 72 00 61 00 64 00 65 00 20 00 61 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 73 00 } //4 Your important files have been encrypted using military grade algorithms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=7
 
}