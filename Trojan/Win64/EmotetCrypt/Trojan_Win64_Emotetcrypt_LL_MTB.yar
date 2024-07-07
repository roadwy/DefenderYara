
rule Trojan_Win64_Emotetcrypt_LL_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 ef c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b d2 90 01 01 8b c7 2b c2 48 63 c8 48 8b 05 90 01 04 0f b6 0c 01 32 0c 1e 88 0b 90 00 } //1
		$a_03_1 = {f7 ee c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 8b d6 ff c6 2b d0 48 8b 05 90 01 04 4c 63 c2 41 8a 14 00 41 32 14 1f 88 13 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}