
rule Trojan_Win32_Icedidcrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Icedidcrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {4e 88 07 8d 5c 1e 09 66 89 1d 90 01 04 a1 90 01 04 8d 44 28 90 01 01 0f b7 c0 89 44 24 90 01 01 0f b7 c3 6b c0 90 01 01 03 05 90 01 04 47 2b e8 83 5c 24 90 01 01 00 85 f6 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}