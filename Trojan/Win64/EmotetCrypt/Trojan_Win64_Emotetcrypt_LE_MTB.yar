
rule Trojan_Win64_Emotetcrypt_LE_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 ?? ?? ?? ?? 89 44 24 ?? 48 8b 0d ?? ?? ?? ?? 8b 44 24 ?? 41 b8 ?? ?? ?? ?? 99 41 f7 f8 8b 44 24 ?? 48 63 d2 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 ?? 48 63 4c 24 ?? 88 14 08 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}