
rule Ransom_Win32_Pocrimcrypt_A_{
	meta:
		description = "Ransom:Win32/Pocrimcrypt.A!!Pocrimcrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 00 6f 00 63 00 6b 00 2e 00 } //1 lock.
		$a_00_1 = {5f 00 63 00 72 00 79 00 70 00 74 00 5f 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 66 00 69 00 6c 00 65 00 } //1 _crypt_encryptfile
		$a_00_2 = {5c 00 6d 00 69 00 63 00 72 00 6f 00 63 00 6f 00 70 00 2e 00 6c 00 6e 00 6b 00 } //2 \microcop.lnk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}