
rule Trojan_BAT_AsyncRAT_PLSH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PLSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 0c 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 08 1e 28 ?? 00 00 06 06 08 28 ?? 00 00 06 02 06 6f ?? 00 00 0a 28 ?? 00 00 06 13 04 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 07 39 ?? 00 00 00 07 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}