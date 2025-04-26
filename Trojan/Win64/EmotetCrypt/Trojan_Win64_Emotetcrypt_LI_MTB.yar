
rule Trojan_Win64_Emotetcrypt_LI_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0a ff 41 88 49 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}