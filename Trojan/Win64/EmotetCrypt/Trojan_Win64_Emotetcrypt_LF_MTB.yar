
rule Trojan_Win64_Emotetcrypt_LF_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c2 f7 ee c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c6 ff c6 6b d2 90 01 01 2b c2 48 63 c8 42 0f b6 04 01 43 32 44 11 90 01 01 48 ff cf 41 88 42 90 01 01 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}