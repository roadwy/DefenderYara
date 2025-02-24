
rule Ransom_Linux_Beast_A_MTB{
	meta:
		description = "Ransom:Linux/Beast.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 4e 43 52 59 50 54 45 52 3a 20 44 41 45 4d 4f 4e } //1 ENCRYPTER: DAEMON
		$a_01_1 = {62 65 61 73 74 2e 6c 6f 67 } //1 beast.log
		$a_01_2 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 20 32 3e 26 31 } //1 vim-cmd vmsvc/getallvms 2>&1
		$a_03_3 = {2d 70 3d 35 20 2d 65 3d ?? 42 45 41 53 54 57 41 53 48 45 52 45 ?? 20 2d 78 3d ?? 52 45 41 44 4d 45 2e 54 58 54 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}