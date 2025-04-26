
rule Ransom_Win32_Vaultcrypt_A_{
	meta:
		description = "Ransom:Win32/Vaultcrypt.A!!Vaultcrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 75 62 20 57 69 6e 64 6f 77 5f 4f 6e 6c 6f 61 64 } //1 sub Window_Onload
		$a_00_1 = {2e 76 61 75 6c 74 00 } //1
		$a_00_2 = {2e 78 6c 73 7c 2e 64 6f 63 7c 2e 72 74 66 } //1 .xls|.doc|.rtf
		$a_00_3 = {7c 70 72 6f 67 72 61 6d 7c 61 76 61 74 61 72 7c } //1 |program|avatar|
		$a_00_4 = {30 31 46 4e 53 48 2d 25 64 } //1 01FNSH-%d
		$a_00_5 = {46 48 41 53 48 2d 25 64 } //1 FHASH-%d
		$a_00_6 = {3d 22 68 74 74 70 3a 2f 2f 74 6f 72 73 63 72 65 65 6e 2e 6f 72 67 } //1 ="http://torscreen.org
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}