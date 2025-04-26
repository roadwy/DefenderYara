
rule Trojan_BAT_Discord_MC_MTB{
	meta:
		description = "Trojan:BAT/Discord.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {42 6f 72 64 65 72 5f 4d 6f 75 73 65 44 6f 77 6e } //1 Border_MouseDown
		$a_01_1 = {65 6e 63 72 79 70 74 5f 4d 6f 75 73 65 44 6f 77 6e } //1 encrypt_MouseDown
		$a_01_2 = {46 00 75 00 72 00 6b 00 42 00 79 00 74 00 65 00 43 00 6f 00 64 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 FurkByteCode.dll
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_7 = {70 4c 76 38 70 4a 73 78 75 4f } //1 pLv8pJsxuO
		$a_01_8 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}