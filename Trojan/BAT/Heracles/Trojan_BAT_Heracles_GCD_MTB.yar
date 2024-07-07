
rule Trojan_BAT_Heracles_GCD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {6d 00 6c 00 75 00 5a 00 79 00 41 00 39 00 49 00 43 00 52 00 54 00 55 00 55 00 78 00 51 00 59 00 58 00 4a 00 68 00 62 00 58 00 4d 00 4e 00 43 00 } //1 mluZyA9ICRTUUxQYXJhbXMNC
		$a_01_2 = {47 00 46 00 7a 00 64 00 46 00 64 00 79 00 61 00 58 00 52 00 6c 00 56 00 47 00 6c 00 74 00 5a 00 } //1 GFzdFdyaXRlVGltZ
		$a_01_3 = {62 00 6c 00 4e 00 30 00 63 00 6d 00 6c 00 75 00 5a 00 79 00 41 00 39 00 49 00 43 00 } //1 blN0cmluZyA9IC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}