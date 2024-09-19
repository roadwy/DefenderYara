
rule Ransom_Win32_LynxCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/LynxCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 79 00 6e 00 78 00 } //1 .lynx
		$a_01_1 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 README.txt
		$a_01_2 = {5c 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 6a 00 70 00 67 00 } //1 \background-image.jpg
		$a_01_3 = {57 57 39 31 63 69 42 6b 59 58 52 68 49 47 6c 7a 49 48 4e 30 62 32 78 6c 62 69 42 68 62 6d 51 67 5a 57 35 6a 63 6e 6c 77 64 47 56 6b 4c 67 30 4b } //4 WW91ciBkYXRhIGlzIHN0b2xlbiBhbmQgZW5jcnlwdGVkLg0K
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4) >=6
 
}