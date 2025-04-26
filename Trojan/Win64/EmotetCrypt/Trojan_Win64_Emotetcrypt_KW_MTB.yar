
rule Trojan_Win64_Emotetcrypt_KW_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 d8 49 f7 e6 48 89 de 48 29 d6 48 d1 ee 48 01 d6 48 c1 ee ?? 48 89 f0 48 c1 e0 ?? 48 29 c6 31 c9 31 d2 41 ff d7 48 03 35 ?? ?? ?? ?? 0f b6 04 33 42 32 04 23 88 04 1f 48 83 c3 ?? 48 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8b cb f7 eb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 48 ff ce 74 ?? 4c 8b 0d ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}