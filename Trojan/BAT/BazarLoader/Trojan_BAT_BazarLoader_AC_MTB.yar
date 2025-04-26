
rule Trojan_BAT_BazarLoader_AC_MTB{
	meta:
		description = "Trojan:BAT/BazarLoader.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {13 02 20 06 00 00 00 38 5e ff ff ff 11 01 11 04 1f 7f 5f 1d 11 03 5a 1c 58 1f 1f 5f 62 60 13 01 38 a9 ff ff ff 11 01 66 2a 11 01 2a 16 13 00 } //10
		$a_80_1 = {53 65 63 75 72 69 74 79 46 69 78 2e 50 72 6f 70 65 72 74 69 65 73 } //SecurityFix.Properties  3
		$a_80_2 = {50 6c 65 64 74 6f 72 67 } //Pledtorg  3
		$a_80_3 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //System.Security.Cryptography.AesCryptoServiceProvider  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}