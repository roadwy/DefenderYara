
rule Trojan_BAT_InjectorCrypt_A_MTB{
	meta:
		description = "Trojan:BAT/InjectorCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5f 00 65 00 6e 00 63 00 } //1 explorer_enc
		$a_00_1 = {52 43 34 64 65 63 72 79 70 74 } //1 RC4decrypt
		$a_00_2 = {52 43 32 44 65 63 72 79 70 74 } //1 RC2Decrypt
		$a_00_3 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //1 EntryPoint
		$a_00_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_5 = {65 78 70 6c 6f 72 65 72 2e 52 65 73 6f 75 72 63 65 73 } //1 explorer.Resources
		$a_02_6 = {5a 49 50 20 52 43 32 20 52 43 34 5c 64 65 63 6f 64 65 5c 90 02 30 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 65 78 70 6c 6f 72 65 72 2e 70 64 62 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=6
 
}