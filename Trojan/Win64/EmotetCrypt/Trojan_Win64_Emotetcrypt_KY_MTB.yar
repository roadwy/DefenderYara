
rule Trojan_Win64_Emotetcrypt_KY_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 41 32 4c 3e ?? 88 4f ?? 48 ff ce 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}