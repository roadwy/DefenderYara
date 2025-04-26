
rule Trojan_BAT_Injector_NITA_MTB{
	meta:
		description = "Trojan:BAT/Injector.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 01 00 02 74 ?? 00 00 01 08 20 00 04 00 00 d6 17 da 17 d6 8d ?? 00 00 01 28 ?? ?? 00 0a 74 ?? 00 00 1b 10 00 07 02 08 20 00 04 00 00 6f ?? ?? 00 0a 0d 08 09 d6 0c 09 20 00 04 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Injector_NITA_MTB_2{
	meta:
		description = "Trojan:BAT/Injector.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 04 1f 0c 58 28 ?? 00 00 0a 0c 03 04 1f 10 58 28 ?? 00 00 0a 0d 03 04 1f 14 58 28 ?? 00 00 0a 13 04 09 2c 3e 09 8d 2f 00 00 01 13 05 03 11 04 11 05 16 11 05 8e 69 28 ?? 00 00 0a 7e 08 00 00 04 7e 02 00 00 04 7b 0a 00 00 04 02 08 58 11 05 11 05 8e 69 0f 03 6f ?? 00 00 06 2d 06 73 2e 00 00 0a 7a 04 1f 28 58 10 02 07 17 58 0b 07 06 32 8f } //2
		$a_01_1 = {4c 6f 67 45 6e 63 72 79 70 74 69 6f 6e 52 65 73 75 6c 74 } //1 LogEncryptionResult
		$a_01_2 = {73 68 65 6c 6c 63 6f 64 65 } //1 shellcode
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}