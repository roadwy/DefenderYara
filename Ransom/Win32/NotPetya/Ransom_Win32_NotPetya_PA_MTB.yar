
rule Ransom_Win32_NotPetya_PA_MTB{
	meta:
		description = "Ransom:Win32/NotPetya.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 45 41 44 4d 45 2e 54 58 54 } //1 \README.TXT
		$a_01_1 = {45 6e 63 72 79 70 74 69 6e 67 43 34 46 75 6e 21 } //1 EncryptingC4Fun!
		$a_03_2 = {5c 50 61 79 6c 6f 61 64 73 5c 4e 6f 74 5f 50 65 74 79 61 5f 58 4f 52 5f 44 6c 6c 5c [0-08] 5c 52 65 6c 65 61 73 65 5c 4e 6f 74 5f 50 65 74 79 61 5f 44 6c 6c 2e 70 64 62 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}