
rule Ransom_Win32_VoidCrypt_PC_MTB{
	meta:
		description = "Ransom:Win32/VoidCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 44 65 63 72 79 70 74 2d 69 6e 66 6f 2e 74 78 74 } //1 \Decrypt-info.txt
		$a_01_1 = {2f 76 6f 69 64 63 72 79 70 74 2f 69 6e 64 65 78 2e 70 68 70 } //1 /voidcrypt/index.php
		$a_01_2 = {46 75 63 6b 69 6e 67 20 74 68 69 73 20 63 6f 75 6e 74 72 79 20 69 73 20 66 6f 72 62 69 64 64 65 6e } //1 Fucking this country is forbidden
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d 20 77 69 74 68 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 All your files are encrypted due to security problem with your computer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}