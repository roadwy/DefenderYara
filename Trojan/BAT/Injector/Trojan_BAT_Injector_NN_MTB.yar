
rule Trojan_BAT_Injector_NN_MTB{
	meta:
		description = "Trojan:BAT/Injector.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 72 79 70 74 65 72 5c 41 64 65 6c 54 75 74 6f 72 69 61 6c 73 } //Crypter\AdelTutorials  5
		$a_80_1 = {43 72 79 70 74 65 72 5c 73 65 72 76 65 72 31 } //Crypter\server1  5
		$a_80_2 = {65 6e 63 72 79 70 74 65 64 } //encrypted  1
		$a_80_3 = {47 65 6e 65 72 61 74 65 50 61 73 73 77 6f 72 64 } //GeneratePassword  1
		$a_80_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_5 = {41 45 53 5f 44 65 63 72 79 70 74 } //AES_Decrypt  1
		$a_80_6 = {4e 74 52 65 61 64 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //NtReadVirtualMemory  1
		$a_80_7 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //NtUnmapViewOfSection  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=16
 
}