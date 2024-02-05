
rule Trojan_Win32_Icedidcrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/Icedidcrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b f7 83 c4 0c a2 90 01 04 89 35 90 01 04 8b 35 90 01 04 43 46 2b db 46 03 db 83 ee 90 01 01 43 ff d6 90 0a 3c 00 0f b6 05 90 01 04 2a 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}