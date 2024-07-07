
rule Trojan_Win64_Emotetcrypt_ME_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 99 44 8b 4d 90 01 01 41 f7 f9 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d 90 01 04 4c 63 55 90 01 01 46 88 1c 11 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}