
rule Trojan_Win64_Emotetcrypt_LN_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 2b d3 83 c3 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 d2 48 6b d2 ?? 48 03 d0 41 8a 04 10 41 32 04 3c 88 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}