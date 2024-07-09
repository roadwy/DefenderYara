
rule Trojan_Win64_Emotetcrypt_LG_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}