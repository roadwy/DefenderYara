
rule Trojan_Win64_Emotetcrypt_LQ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b cb 2b c8 48 63 d1 48 8b 05 ?? ?? ?? ?? 0f b6 0c 02 32 0c 3e 88 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}