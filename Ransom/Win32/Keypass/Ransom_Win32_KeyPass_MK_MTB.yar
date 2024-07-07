
rule Ransom_Win32_KeyPass_MK_MTB{
	meta:
		description = "Ransom:Win32/KeyPass.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {21 21 21 57 48 59 5f 4d 59 5f 46 49 4c 45 53 5f 4e 4f 54 5f 4f 50 45 4e 21 21 21 2e 74 78 74 } //!!!WHY_MY_FILES_NOT_OPEN!!!.txt  1
		$a_80_1 = {69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //important files are encrypted  1
		$a_80_2 = {50 72 69 63 65 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e } //Price for decryption  1
		$a_80_3 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 69 64 3a } //Your personal id:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}