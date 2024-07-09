
rule Trojan_BAT_AsyncRat_AAYQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AAYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 1f 10 8d ?? 00 00 01 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 26 06 08 6f ?? 00 00 0a 07 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 09 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 de 2a } //2
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}