
rule Trojan_Win64_LummaStealer_NITA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 "
		
	strings :
		$a_01_0 = {66 44 39 34 41 74 6a ff 15 75 82 07 00 85 c0 74 5c 48 8b 4d 30 4c 8d 45 38 48 8d 55 30 ff c3 e8 9e e6 ff ff 8b c8 85 c0 78 0f 48 8b 4d 30 48 85 c9 74 48 48 8b 45 38 eb c7 } //2
		$a_01_1 = {48 8d 4c 24 78 48 8d 1d 03 89 07 00 ff 15 8d 5d 07 00 0f b7 44 24 78 48 8d 0d e9 88 07 00 bf 05 00 00 00 85 c0 } //2
		$a_00_2 = {73 00 74 00 69 00 6d 00 75 00 6c 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //2 stimulate.exe
		$a_01_3 = {44 65 6c 65 74 69 6e 67 20 66 69 6c 65 } //2 Deleting file
		$a_01_4 = {65 78 74 72 61 63 74 20 70 61 79 6c 6f 61 64 73 } //2 extract payloads
		$a_01_5 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 65 6c 65 76 61 74 65 64 20 65 6e 67 69 6e 65 } //2 Connected to elevated engine
		$a_01_6 = {44 65 63 72 79 70 74 46 69 6c 65 57 } //1 DecryptFileW
		$a_01_7 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
		$a_01_8 = {6c 6f 61 64 20 61 20 64 65 63 72 79 70 74 69 6f 6e 20 6d 65 74 68 6f 64 } //1 load a decryption method
		$a_01_9 = {72 6f 6c 6c 62 61 63 6b 20 69 73 20 64 69 73 61 62 6c 65 64 } //1 rollback is disabled
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=16
 
}