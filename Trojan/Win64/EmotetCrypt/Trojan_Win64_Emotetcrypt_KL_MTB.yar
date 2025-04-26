
rule Trojan_Win64_Emotetcrypt_KL_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 83 c6 03 6b d2 ?? 2b c2 83 c0 02 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 4c 3b ?? 49 ff cc 88 4f ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}