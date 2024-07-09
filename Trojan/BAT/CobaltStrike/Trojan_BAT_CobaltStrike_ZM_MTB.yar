
rule Trojan_BAT_CobaltStrike_ZM_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {7e 12 00 00 0a 11 06 28 ?? ?? ?? 0a 26 7e ?? ?? ?? 0a 11 06 28 ?? ?? ?? 0a 13 07 11 07 08 09 28 ?? ?? ?? 06 13 08 11 08 28 03 00 00 0a 73 17 00 00 0a 13 09 11 05 11 09 6f 18 00 00 0a 26 11 04 28 03 00 00 0a 73 17 00 00 0a 13 0a 11 05 11 0a 6f 18 00 00 0a } //1
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 54 65 78 74 } //1 encryptedText
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {44 65 63 72 79 70 74 41 45 53 } //1 DecryptAES
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}