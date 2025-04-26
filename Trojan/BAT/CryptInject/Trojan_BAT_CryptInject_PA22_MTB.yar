
rule Trojan_BAT_CryptInject_PA22_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PA22!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {17 2d 06 d0 41 00 00 06 26 7e 11 00 00 04 02 91 0a 02 17 58 fe 0b 00 00 38 7c 00 00 00 7e 11 00 00 04 02 91 1f 40 5f 2d 2f 1d 45 01 00 00 00 f6 ff ff ff 7e 11 00 00 04 02 91 20 7f ff ff ff 5f 1e 62 0a 06 7e 11 00 00 04 02 17 58 91 60 0a 02 18 58 fe 0b 00 00 2b 41 7e 11 00 00 04 02 91 20 3f ff ff ff 5f 1f 18 62 0a 06 7e 11 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e 11 00 00 04 02 18 58 91 1e 62 60 0a 06 7e 11 00 00 04 02 19 58 91 60 0a 02 1a 58 fe 0b 00 00 06 17 2f 10 } //5
		$a_01_1 = {47 65 74 52 75 6e 74 69 6d 65 44 69 72 65 63 74 6f 72 79 } //1 GetRuntimeDirectory
		$a_80_2 = {53 46 5a 77 54 30 77 6b } //SFZwT0wk  1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}