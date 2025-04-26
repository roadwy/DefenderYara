
rule Trojan_BAT_LokiBot_HDF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.HDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  1
		$a_80_1 = {73 61 64 61 64 61 } //sadada  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {4d 79 2e 43 6f 6d 70 75 74 65 72 } //My.Computer  1
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_5 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 } //Dispose__Instance  1
		$a_80_6 = {54 6f 53 74 72 69 6e 67 } //ToString  1
		$a_80_7 = {47 65 74 54 79 70 65 } //GetType  1
		$a_80_8 = {4c 61 74 65 47 65 74 } //LateGet  1
		$a_80_9 = {54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 } //ThreadAttribute  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}