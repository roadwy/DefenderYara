
rule Trojan_Win64_Icedidcrypt_GL_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_02_0 = {41 8a 0a 41 88 08 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 49 ff c0 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 8a 4c 24 ?? 89 54 24 ?? 89 54 24 ?? 8b 35 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? eb } //10
		$a_02_1 = {49 ff c2 ff c5 3b 6c 24 ?? 8a 5c 24 ?? 89 54 24 ?? 89 54 24 ?? 0f 82 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
		$a_80_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10) >=40
 
}