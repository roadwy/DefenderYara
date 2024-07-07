
rule Trojan_Win32_EmotetCrypt_PCX_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 1c 8b 15 90 01 04 8b 44 24 90 01 01 81 e1 ff 00 00 00 8a 14 11 8b 4c 24 90 01 01 8a 1c 08 32 da 88 1c 08 8b 4c 24 90 01 01 40 3b c1 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}