
rule Trojan_Win64_Icedidcrypt_GL_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {41 8a 0a 41 88 08 8a 4c 24 90 01 01 89 54 24 90 01 01 89 54 24 90 01 01 49 ff c0 8a 4c 24 90 01 01 89 54 24 90 01 01 89 54 24 90 01 01 8a 4c 24 90 01 01 89 54 24 90 01 01 89 54 24 90 01 01 8b 35 90 01 04 8b 0d 90 01 04 eb 90 00 } //0a 00 
		$a_02_1 = {49 ff c2 ff c5 3b 6c 24 90 01 01 8a 5c 24 90 01 01 89 54 24 90 01 01 89 54 24 90 01 01 0f 82 90 00 } //0a 00 
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  0a 00 
		$a_80_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  00 00 
	condition:
		any of ($a_*)
 
}