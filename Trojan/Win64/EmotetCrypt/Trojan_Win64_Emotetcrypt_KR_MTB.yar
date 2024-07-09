
rule Trojan_Win64_Emotetcrypt_KR_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 4d f0 0f b6 54 0d 00 48 8b 0d ?? ?? ?? ?? 44 8b 45 f0 89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 b4 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 b0 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 8b 55 f0 44 6b 55 f8 00 44 29 d2 4c 63 ca 46 88 1c 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}