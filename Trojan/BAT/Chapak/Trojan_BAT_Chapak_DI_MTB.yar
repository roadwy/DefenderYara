
rule Trojan_BAT_Chapak_DI_MTB{
	meta:
		description = "Trojan:BAT/Chapak.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_01_1 = {53 00 48 00 4f 00 50 00 50 00 49 00 4e 00 47 00 5f 00 57 00 4f 00 52 00 4c 00 44 00 5f 00 4f 00 4e 00 4c 00 49 00 4e 00 45 00 5f 00 45 00 43 00 4f 00 4d 00 4d 00 45 00 52 00 43 00 45 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 34 00 30 00 } //1 SHOPPING_WORLD_ONLINE_ECOMMERCE_ICON_192440
		$a_81_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_5 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}