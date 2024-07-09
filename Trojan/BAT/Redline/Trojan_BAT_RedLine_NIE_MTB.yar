
rule Trojan_BAT_RedLine_NIE_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {28 84 02 00 0a 26 02 28 ?? ?? 00 0a 0a 28 ?? ?? 00 0a 06 16 06 8e 69 6f ?? ?? 00 0a } //5
		$a_01_1 = {77 79 61 67 63 } //1 wyagc
		$a_01_2 = {75 68 67 66 36 } //1 uhgf6
		$a_01_3 = {42 43 52 59 50 54 5f 44 53 41 5f 4b 45 59 5f 42 4c 4f 42 5f 56 32 53 2e 46 6f 72 6d 33 2e 72 65 73 6f 75 72 63 65 73 } //1 BCRYPT_DSA_KEY_BLOB_V2S.Form3.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}