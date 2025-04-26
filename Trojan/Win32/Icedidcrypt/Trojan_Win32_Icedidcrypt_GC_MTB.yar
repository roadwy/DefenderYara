
rule Trojan_Win32_Icedidcrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/Icedidcrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f7 83 c4 0c a2 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 43 46 2b db 46 03 db 83 ee ?? 43 ff d6 90 0a 3c 00 0f b6 05 ?? ?? ?? ?? 2a 05 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}