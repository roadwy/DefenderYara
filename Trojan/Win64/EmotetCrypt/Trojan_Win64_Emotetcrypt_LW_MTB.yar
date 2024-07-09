
rule Trojan_Win64_Emotetcrypt_LW_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 84 04 ?? ?? ?? ?? 89 44 24 28 48 8b 0d ?? ?? ?? ?? 8b 44 24 30 41 b8 ?? ?? ?? ?? 99 41 f7 f8 8b 44 24 28 48 63 d2 0f b6 0c 11 31 c8 88 c2 48 8b 84 24 98 00 00 00 8b 4c 24 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}