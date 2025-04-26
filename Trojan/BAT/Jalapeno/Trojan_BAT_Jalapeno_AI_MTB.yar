
rule Trojan_BAT_Jalapeno_AI_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {01 0a 06 16 06 8e 69 6f 1a 00 00 0a 26 28 1b 00 00 0a 0b 07 28 1c 00 00 0a } //2
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {67 65 74 5f 47 } //1 get_G
		$a_81_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_81_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}