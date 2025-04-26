
rule Ransom_Win32_Death_DA_MTB{
	meta:
		description = "Ransom:Win32/Death.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 61 6c 75 74 20 43 49 52 43 45 54 21 } //1 Salut CIRCET!
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 48 79 70 65 72 20 2d 20 56 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 2c 20 62 61 63 6b 75 70 73 20 61 6e 64 20 4e 41 53 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 All your files, Hyper - V infrastructure, backups and NASes have been encrypted!
		$a_81_2 = {43 49 52 43 45 54 73 75 70 70 6f 72 74 40 73 65 63 6d 61 69 6c 2e 70 72 6f } //1 CIRCETsupport@secmail.pro
		$a_81_3 = {72 65 61 64 5f 6d 65 5f 6c 6b 64 2e 74 78 74 } //1 read_me_lkd.txt
		$a_81_4 = {48 65 6c 6c 6f 4b 69 74 74 79 4d 75 74 65 78 } //1 HelloKittyMutex
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}