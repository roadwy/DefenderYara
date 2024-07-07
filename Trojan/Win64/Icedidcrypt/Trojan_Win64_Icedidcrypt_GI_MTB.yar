
rule Trojan_Win64_Icedidcrypt_GI_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 84 24 90 01 04 ff c2 0f b6 84 24 90 01 04 0f b6 84 24 90 01 04 f6 c2 01 75 90 02 08 0f b6 03 41 88 00 49 ff c0 0f b6 84 24 90 01 04 ff c1 0f b6 84 24 90 01 04 48 ff c3 0f b6 84 24 90 01 04 8b 84 24 90 01 04 3b c8 72 90 00 } //10
		$a_02_1 = {0f b6 04 11 88 02 48 ff c2 8b 44 24 90 01 01 ff c0 89 44 24 90 01 01 8b 44 24 90 01 01 41 3b c0 72 90 00 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}