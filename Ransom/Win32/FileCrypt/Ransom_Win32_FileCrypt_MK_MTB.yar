
rule Ransom_Win32_FileCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/FileCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {51 6b 6b 62 61 6c } //Qkkbal  2
		$a_80_1 = {78 62 61 73 65 5f 6c 69 62 72 61 72 79 2e 7a 69 70 } //xbase_library.zip  1
		$a_80_2 = {78 62 69 74 63 6f 69 6e 2e 62 6d 70 } //xbitcoin.bmp  1
		$a_80_3 = {78 6c 6f 63 6b 2e 62 6d 70 } //xlock.bmp  1
		$a_80_4 = {78 6c 6f 63 6b 2e 69 63 6f } //xlock.ico  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}