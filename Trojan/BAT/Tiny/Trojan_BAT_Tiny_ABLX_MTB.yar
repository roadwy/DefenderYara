
rule Trojan_BAT_Tiny_ABLX_MTB{
	meta:
		description = "Trojan:BAT/Tiny.ABLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 13 04 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 05 09 11 05 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 06 11 06 06 16 06 8e 69 6f ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 11 08 13 0a de 14 09 2c 06 09 6f ?? ?? ?? 0a dc } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}