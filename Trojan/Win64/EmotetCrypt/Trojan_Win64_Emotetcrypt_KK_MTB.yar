
rule Trojan_Win64_Emotetcrypt_KK_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 eb c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c d2 c1 e1 02 2b c1 48 63 c8 42 8a 04 01 43 32 04 13 41 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}