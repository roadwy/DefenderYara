
rule Ransom_Win32_HiveCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/HiveCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //01 00  Go buildinf:
		$a_01_1 = {63 72 79 70 74 6f 2f 61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b 47 6f } //01 00  crypto/aes.encryptBlockGo
		$a_01_2 = {63 72 79 70 74 6f 2f 61 65 73 2e 65 78 70 61 6e 64 4b 65 79 47 6f } //01 00  crypto/aes.expandKeyGo
		$a_01_3 = {70 61 74 68 2f 66 69 6c 65 70 61 74 68 2e 57 61 6c 6b 44 69 72 } //00 00  path/filepath.WalkDir
	condition:
		any of ($a_*)
 
}