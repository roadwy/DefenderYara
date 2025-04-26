
rule Trojan_BAT_DcRat_NEAF_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 31 63 63 32 62 61 64 2d 64 36 66 37 2d 34 37 62 38 2d 61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //5 d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1
		$a_01_1 = {4e 45 54 53 65 63 75 72 65 2c 20 61 20 2e 4e 45 54 20 6f 62 66 75 73 63 61 74 69 6f 6e 20 70 72 6f 67 72 61 6d } //2 NETSecure, a .NET obfuscation program
		$a_01_2 = {50 72 6f 74 65 63 74 65 64 57 69 74 68 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //2 ProtectedWithCryptoObfuscatorAttribute
		$a_01_3 = {4f 62 66 75 73 63 61 74 65 64 42 79 41 67 69 6c 65 44 6f 74 4e 65 74 41 74 74 72 69 62 75 74 65 } //2 ObfuscatedByAgileDotNetAttribute
		$a_01_4 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //2 BabelObfuscatorAttribute
		$a_01_5 = {41 49 43 75 73 74 6f 6d 50 72 6f 70 65 72 74 79 50 72 6f 76 69 64 65 72 50 72 6f 78 79 } //2 AICustomPropertyProviderProxy
		$a_01_6 = {47 65 74 44 79 6e 61 6d 69 63 49 4c 49 6e 66 6f } //2 GetDynamicILInfo
		$a_01_7 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //2 System.Reflection.Emit
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=19
 
}