
rule Trojan_Win32_Icedidcrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/Icedidcrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {4e 88 07 8d 5c 1e 09 66 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 44 28 ?? 0f b7 c0 89 44 24 ?? 0f b7 c3 6b c0 ?? 03 05 ?? ?? ?? ?? 47 2b e8 83 5c 24 ?? 00 85 f6 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}