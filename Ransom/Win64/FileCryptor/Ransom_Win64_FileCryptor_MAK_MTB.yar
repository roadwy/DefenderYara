
rule Ransom_Win64_FileCryptor_MAK_MTB{
	meta:
		description = "Ransom:Win64/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 41 4e 53 4f 4d 57 41 52 45 5f 4b 44 46 5f 49 4e 46 4f } //RANSOMWARE_KDF_INFO  1
		$a_80_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //expand 32-byte k  1
		$a_80_2 = {73 72 63 2f 62 69 6e 2f 72 61 6e 73 6f 6d 77 61 72 65 2e 72 73 } //src/bin/ransomware.rs  1
		$a_80_3 = {70 61 6e 69 63 20 70 61 79 6c 6f 61 64 } //panic payload  1
		$a_80_4 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //Local\RustBacktraceMutex  1
		$a_80_5 = {4c 61 7a 79 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //Lazy instance has previously been poisoned  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}