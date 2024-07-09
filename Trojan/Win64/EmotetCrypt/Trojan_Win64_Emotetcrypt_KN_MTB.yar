
rule Trojan_Win64_Emotetcrypt_KN_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 0d ?? 48 8b 0d ?? ?? ?? ?? 44 8b 45 ?? 89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 ?? 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 ?? 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 4c 63 4d ?? 46 88 1c 09 8b 45 ?? 83 c0 01 89 45 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}