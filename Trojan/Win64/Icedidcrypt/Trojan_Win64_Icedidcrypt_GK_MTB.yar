
rule Trojan_Win64_Icedidcrypt_GK_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 1e 00 04 00 00 "
		
	strings :
		$a_02_0 = {88 0a 8a 0f 89 45 00 89 45 04 48 ff c2 48 89 55 ?? 8a 0f 89 45 00 89 45 04 8a 0f 89 45 00 89 45 04 eb } //10
		$a_02_1 = {41 ff c0 48 8b 4d ?? 44 3b 01 8a 0f 89 45 00 89 45 04 73 ?? 48 ff c3 48 89 5d ?? 8b 0d ?? ?? ?? ?? 44 8b 1d ?? ?? ?? ?? 44 89 d3 e9 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
		$a_80_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10) >=30
 
}