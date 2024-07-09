
rule Trojan_Win64_Emotetcrypt_MB_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 84 04 [0-04] 89 44 24 [0-04] 8b 44 24 [0-04] 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 [0-04] 33 c8 8b c1 8b 0d ?? ?? ?? ?? 8b 54 24 [0-05] d1 8b ca } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}