
rule Trojan_Win64_Emotetcrypt_LC_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 88 4f ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c6 83 c6 ?? 6b d2 ?? 2b c2 83 c0 ?? 48 63 c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 01 32 4c 3b ?? 49 ff cc 88 4f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}