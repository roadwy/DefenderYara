
rule Trojan_Win64_IcedID_ML_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } //01 00  RunObject
		$a_01_1 = {56 4d 70 42 72 4b 2e 64 6c 6c } //01 00  VMpBrK.dll
		$a_01_2 = {41 4d 66 46 43 6c 47 72 58 6b 59 } //01 00  AMfFClGrXkY
		$a_01_3 = {42 58 6f 62 59 76 50 46 6e 71 75 } //01 00  BXobYvPFnqu
		$a_01_4 = {44 4e 71 72 5a 73 48 56 71 66 } //01 00  DNqrZsHVqf
		$a_01_5 = {50 52 6f 72 41 73 72 53 77 } //00 00  PRorAsrSw
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ML_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 89 04 24 48 8b 44 24 08 eb 00 48 ff c0 48 89 44 24 08 eb d4 eb 47 48 89 4c 24 08 48 83 ec 28 eb 31 48 8b 44 24 40 48 ff c8 eb 40 8a 09 88 08 eb } //05 00 
		$a_01_1 = {48 89 44 24 08 48 8b 44 24 30 eb 46 48 ff c0 48 89 04 24 eb 00 48 8b 44 24 08 48 ff c0 eb e1 48 89 4c 24 08 48 83 ec 18 eb 00 48 8b 44 24 20 48 89 04 24 eb 29 88 08 48 8b 04 24 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ML_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 61 65 73 32 35 36 67 63 6d 5f 61 62 79 74 65 73 } //01 00  rrypto_aead_aes256gcm_abytes
		$a_01_1 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 61 65 73 32 35 36 67 63 6d 5f 64 65 63 72 79 70 74 } //01 00  rrypto_aead_aes256gcm_decrypt
		$a_01_2 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 61 65 73 32 35 36 67 63 6d 5f 65 6e 63 72 79 70 74 } //01 00  rrypto_aead_aes256gcm_encrypt
		$a_01_3 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 61 65 73 32 35 36 67 63 6d 5f 6b 65 79 62 79 74 65 73 } //01 00  rrypto_aead_aes256gcm_keybytes
		$a_01_4 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 61 65 73 32 35 36 67 63 6d 5f 6e 73 65 63 62 79 74 65 73 } //01 00  rrypto_aead_aes256gcm_nsecbytes
		$a_01_5 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 63 68 61 63 68 61 32 30 70 6f 6c 79 31 33 30 35 5f 61 62 79 74 65 73 } //01 00  rrypto_aead_chacha20poly1305_abytes
		$a_01_6 = {72 72 79 70 74 6f 5f 61 65 61 64 5f 63 68 61 63 68 61 32 30 70 6f 6c 79 31 33 30 35 5f 64 65 63 72 79 70 74 } //01 00  rrypto_aead_chacha20poly1305_decrypt
		$a_01_7 = {72 72 79 70 74 6f 5f 61 75 74 68 5f 62 79 74 65 73 } //00 00  rrypto_auth_bytes
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_ML_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 06 83 c0 1e 48 98 0f b7 4c 45 00 48 81 c1 6f 04 00 00 4b 31 0c c7 } //00 00 
	condition:
		any of ($a_*)
 
}