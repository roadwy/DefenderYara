
rule Ransom_AndroidOS_CryCryptor_B{
	meta:
		description = "Ransom:AndroidOS/CryCryptor.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {63 6f 6d 2e 90 02 20 2e 41 43 54 49 4f 4e 5f 45 4e 43 52 59 50 54 45 44 90 00 } //01 00 
		$a_02_1 = {63 6f 6d 2e 90 02 20 2e 50 41 53 53 57 4f 52 44 90 00 } //01 00 
		$a_00_2 = {2f 72 65 61 64 6d 65 } //01 00  /readme
		$a_00_3 = {55 6e 6c 6f 63 6b 65 64 2e 20 50 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 64 65 63 72 79 70 74 65 64 } //01 00  Unlocked. Personal files decrypted
		$a_00_4 = {2e 65 6e 63 } //00 00  .enc
	condition:
		any of ($a_*)
 
}