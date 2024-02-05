
rule Trojan_Win64_Icedidcrypt_GK_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {88 0a 8a 0f 89 45 00 89 45 04 48 ff c2 48 89 55 90 01 01 8a 0f 89 45 00 89 45 04 8a 0f 89 45 00 89 45 04 eb 90 00 } //0a 00 
		$a_02_1 = {41 ff c0 48 8b 4d 90 01 01 44 3b 01 8a 0f 89 45 00 89 45 04 73 90 01 01 48 ff c3 48 89 5d 90 01 01 8b 0d 90 01 04 44 8b 1d 90 01 04 44 89 d3 e9 90 00 } //0a 00 
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  0a 00 
		$a_80_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  00 00 
	condition:
		any of ($a_*)
 
}