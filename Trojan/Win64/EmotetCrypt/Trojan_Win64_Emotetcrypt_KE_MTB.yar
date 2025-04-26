
rule Trojan_Win64_Emotetcrypt_KE_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 89 88 88 88 f7 eb 03 d3 c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 6b d2 1e 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 54 3d 00 88 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}