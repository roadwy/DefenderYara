
rule Trojan_Win64_Emotetcrypt_LB_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 38 33 c8 8b c1 8b 4c 24 24 0f af 4c 24 24 8b 54 24 20 03 d1 8b ca 48 63 c9 48 8b 54 24 40 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}