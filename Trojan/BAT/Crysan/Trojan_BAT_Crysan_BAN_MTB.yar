
rule Trojan_BAT_Crysan_BAN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 09 1a 5a 28 ?? 00 00 0a 6e 7e ?? 00 00 04 8e 69 6a 5e 13 04 07 7e ?? 00 00 04 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 93 6f ?? 00 00 0a 26 09 17 58 0d 09 02 32 ca } //2
		$a_01_1 = {57 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 54 00 6f 00 20 00 4b 00 72 00 65 00 59 00 7a 00 65 00 54 00 65 00 6d 00 70 00 20 00 53 00 70 00 6f 00 6f 00 66 00 65 00 72 00 } //1 Welcome To KreYzeTemp Spoofer
		$a_01_2 = {62 00 72 00 75 00 68 00 20 00 77 00 68 00 61 00 74 00 20 00 74 00 68 00 65 00 20 00 66 00 75 00 63 00 6b 00 } //1 bruh what the fuck
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}