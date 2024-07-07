
rule Ransom_Win32_Zatnacrypt_A{
	meta:
		description = "Ransom:Win32/Zatnacrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 75 70 65 72 73 65 63 72 65 74 70 61 73 73 } //1 supersecretpass
		$a_01_1 = {2e 76 73 63 72 79 70 74 } //1 .vscrypt
		$a_01_2 = {3a 5c 76 73 77 6f 72 6b 64 69 72 } //1 :\vsworkdir
		$a_01_3 = {2a 2e 70 64 66 } //1 *.pdf
		$a_01_4 = {5c 00 73 00 68 00 61 00 6e 00 74 00 61 00 7a 00 68 00 2e 00 6a 00 70 00 67 00 } //1 \shantazh.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}