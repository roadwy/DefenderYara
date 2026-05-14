
rule Trojan_BAT_AsyncRAT_ARAX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 08 03 08 91 04 08 04 8e 69 5d 91 61 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d d5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AsyncRAT_ARAX_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 02 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 38 00 00 00 00 00 11 04 02 16 02 8e 69 6f ?? 00 00 0a } //5
		$a_03_1 = {11 0a 11 02 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 09 38 00 00 00 00 00 11 09 02 16 02 8e 69 6f ?? 00 00 0a } //5
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}