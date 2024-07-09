
rule Trojan_Win64_Emotetcrypt_LD_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b d3 ff c3 2b d0 48 8b 05 ?? ?? ?? ?? 4c 63 c2 41 8a 14 00 42 32 14 37 88 17 48 ff c7 49 ff cf 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}