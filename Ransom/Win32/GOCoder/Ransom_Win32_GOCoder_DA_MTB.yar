
rule Ransom_Win32_GOCoder_DA_MTB{
	meta:
		description = "Ransom:Win32/GOCoder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 ffffff8c 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 67 53 64 51 78 36 55 5f 6b 6b 50 45 53 32 39 35 63 45 73 4d } //100 Go build ID: "gSdQx6U_kkPES295cEsM
		$a_81_1 = {47 6f 2f 73 72 63 2f 69 6e 74 65 72 6e 61 6c 2f 63 68 61 63 68 61 38 72 61 6e 64 2f 63 68 61 63 68 61 38 2e 67 6f } //10 Go/src/internal/chacha8rand/chacha8.go
		$a_81_2 = {63 72 79 70 74 6f 2f 69 6e 74 65 72 6e 61 6c 2f 66 69 70 73 31 34 30 2f 61 65 73 2e 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 53 63 68 65 64 75 6c 65 } //10 crypto/internal/fips140/aes.EncryptionKeySchedule
		$a_81_3 = {63 72 79 70 74 6f 2f 69 6e 74 65 72 6e 61 6c 2f 66 69 70 73 31 34 30 2f 61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b 41 73 6d } //10 crypto/internal/fips140/aes.encryptBlockAsm
		$a_81_4 = {5f 65 78 70 61 6e 64 5f 6b 65 79 5f } //10 _expand_key_
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10) >=140
 
}