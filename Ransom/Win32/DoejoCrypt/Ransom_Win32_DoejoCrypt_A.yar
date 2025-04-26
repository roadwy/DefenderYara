
rule Ransom_Win32_DoejoCrypt_A{
	meta:
		description = "Ransom:Win32/DoejoCrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your file has been encrypted!
		$a_01_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 63 72 79 70 74 2c 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 2e } //1 If you want to decrypt, please contact us.
		$a_01_2 = {41 6e 64 20 70 6c 65 61 73 65 20 73 65 6e 64 20 6d 65 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 68 61 73 68 21 } //1 And please send me the following hash!
		$a_01_3 = {64 65 61 72 21 21 21 } //1 dear!!!
		$a_01_4 = {63 72 65 61 74 65 20 72 73 61 20 65 72 72 6f 72 } //1 create rsa error
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}