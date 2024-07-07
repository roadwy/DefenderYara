
rule Ransom_Win32_QilinCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/QilinCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe delete shadows /all /quiet  1
		$a_80_1 = {2d 2d 20 51 69 6c 69 6e } //-- Qilin  1
		$a_80_2 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 2f 73 79 73 74 65 6d 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 } //Your network/system was encrypted  1
		$a_80_3 = {52 45 41 44 4d 45 2d 52 45 43 4f 56 45 52 2d 2e 74 78 74 } //README-RECOVER-.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}