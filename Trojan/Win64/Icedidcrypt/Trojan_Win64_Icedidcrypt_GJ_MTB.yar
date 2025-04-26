
rule Trojan_Win64_Icedidcrypt_GJ_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 d3 30 c3 bb ?? ?? ?? ?? 41 0f 45 dd 84 c0 89 d8 41 0f 45 c5 84 d2 0f 44 c3 eb } //10
		$a_00_1 = {8d 48 ff 0f af c8 44 31 e1 83 c9 fe 44 39 e1 0f 94 c0 83 fa 0a 0f 9c c3 30 c3 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}
rule Trojan_Win64_Icedidcrypt_GJ_MTB_2{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 00 48 8b 8c 24 ?? ?? ?? ?? 88 01 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 48 8b ac 24 ?? ?? ?? ?? 48 ff c5 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 } //10
		$a_02_1 = {49 ff c6 8a 44 24 ?? 44 89 6c 24 ?? 44 89 6c 24 ?? 0f 57 c0 f2 0f 2a 44 24 ?? f2 0f 11 44 24 ?? 8b 84 24 ?? ?? ?? ?? 89 44 24 ?? b8 ?? ?? ?? ?? 44 8b 64 24 ?? e9 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}