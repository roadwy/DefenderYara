
rule Ransom_Win32_AvosLocker_PAC_MTB{
	meta:
		description = "Ransom:Win32/AvosLocker.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 20 77 69 6c 6c 20 62 65 20 63 6f 72 72 75 70 74 65 64 20 69 66 20 61 20 73 68 75 74 64 6f 77 6e 20 6f 63 63 75 72 73 20 64 75 72 69 6e 67 20 74 68 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 70 72 6f 63 65 73 73 2e } //1 Your documents will be corrupted if a shutdown occurs during the encryption process.
		$a_01_1 = {5a 61 76 6f 73 20 61 76 6f 73 6c 69 6e 75 78 20 61 76 6f 73 } //1 Zavos avoslinux avos
		$a_01_2 = {42 72 75 74 65 66 6f 72 63 65 20 53 4d 42 } //1 Bruteforce SMB
		$a_01_3 = {64 69 73 61 62 6c 65 64 72 69 76 65 73 } //1 disabledrives
		$a_01_4 = {44 69 73 61 62 6c 65 20 6d 75 74 65 78 } //1 Disable mutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}