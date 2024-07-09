
rule Trojan_Win64_Emotetcrypt_LS_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8d 0c d2 03 c9 8b c7 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 0c 1e 88 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}