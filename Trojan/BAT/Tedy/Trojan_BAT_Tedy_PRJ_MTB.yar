
rule Trojan_BAT_Tedy_PRJ_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 07 17 6f ?? 00 00 0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d de 1e 08 2c 06 08 } //5
		$a_00_1 = {45 4e 43 5f 50 41 59 4c 4f 41 44 } //3 ENC_PAYLOAD
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}