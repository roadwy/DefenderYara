
rule Trojan_Win64_Emotetcrypt_LC_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 88 4f 90 01 01 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c6 83 c6 90 01 01 6b d2 90 01 01 2b c2 83 c0 90 01 01 48 63 c8 48 8b 05 90 01 04 0f b6 0c 01 32 4c 3b 90 01 01 49 ff cc 88 4f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}