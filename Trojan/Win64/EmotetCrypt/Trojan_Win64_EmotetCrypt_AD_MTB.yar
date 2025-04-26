
rule Trojan_Win64_EmotetCrypt_AD_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c9 48 2b c1 48 63 0d ?? ?? ?? ?? 48 2b c1 48 8b 4c 24 ?? 0f b6 04 01 8b 4c 24 ?? 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 2b 0d ?? ?? ?? ?? 48 63 c9 48 8b 54 24 ?? 88 04 0a e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}