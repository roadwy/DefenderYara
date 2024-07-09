
rule Trojan_Win64_Emotetcrypt_KS_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c0 4c 2b c8 b8 ?? ?? ?? ?? f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 01 43 32 14 01 41 88 10 49 ff c0 48 ff cf 75 } //1
		$a_03_1 = {4c 8b c0 4c 2b c8 b8 ?? ?? ?? ?? f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 8a 14 01 43 32 14 01 41 88 10 49 ff c0 48 ff cf 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}