
rule Trojan_Win64_Emotetcrypt_LZ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 04 50 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 83 e2 0f 03 c2 83 e0 0f 2b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}