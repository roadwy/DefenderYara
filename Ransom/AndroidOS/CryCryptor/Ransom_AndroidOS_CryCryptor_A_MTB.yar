
rule Ransom_AndroidOS_CryCryptor_A_MTB{
	meta:
		description = "Ransom:AndroidOS/CryCryptor.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 72 79 64 72 6f 69 64 2e 41 43 54 49 4f 4e 5f 44 45 43 52 59 50 54 45 44 } //1 com.crydroid.ACTION_DECRYPTED
		$a_00_1 = {63 6f 6d 2e 63 72 79 64 72 6f 69 64 2e 50 41 53 53 57 4f 52 44 } //1 com.crydroid.PASSWORD
		$a_00_2 = {55 6e 6c 6f 63 6b 65 64 2e 20 50 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 64 65 63 72 79 70 74 65 64 } //1 Unlocked. Personal files decrypted
		$a_00_3 = {50 42 4b 44 46 32 57 69 74 68 48 6d 61 63 53 48 41 31 } //1 PBKDF2WithHmacSHA1
		$a_01_4 = {2f 72 65 61 64 6d 65 5f 6e 6f 77 2e 74 78 74 } //1 /readme_now.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}