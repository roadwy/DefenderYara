
rule Trojan_Win64_Emotetcrypt_LE_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 90 01 04 89 44 24 90 01 01 48 8b 0d 90 01 04 8b 44 24 90 01 01 41 b8 90 01 04 99 41 f7 f8 8b 44 24 90 01 01 48 63 d2 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 90 01 01 48 63 4c 24 90 01 01 88 14 08 8b 44 24 90 01 01 83 c0 90 01 01 89 44 24 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}