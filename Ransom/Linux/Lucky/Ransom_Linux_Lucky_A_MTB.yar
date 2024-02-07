
rule Ransom_Linux_Lucky_A_MTB{
	meta:
		description = "Ransom:Linux/Lucky.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 6d 65 20 66 69 6c 65 73 20 68 61 73 20 63 72 79 70 74 65 64 } //01 00  Some files has crypted
		$a_00_1 = {69 66 20 79 6f 75 20 77 61 6e 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 20 2c 20 73 65 6e 64 20 31 20 62 69 74 63 6f 69 6e 20 74 6f 20 6d 79 20 77 61 6c 6c 65 74 } //01 00  if you want your files back , send 1 bitcoin to my wallet
		$a_00_2 = {2f 72 6f 6f 74 2f 48 6f 77 5f 54 6f 5f 44 65 63 72 79 70 74 5f 4d 79 5f 46 69 6c 65 } //01 00  /root/How_To_Decrypt_My_File
		$a_00_3 = {72 73 61 5f 63 72 70 74 2e 63 } //01 00  rsa_crpt.c
		$a_00_4 = {2f 74 6d 70 2f 53 73 65 73 73 69 6f 6e } //00 00  /tmp/Ssession
	condition:
		any of ($a_*)
 
}