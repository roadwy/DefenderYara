
rule Trojan_Win64_Emotetcrypt_KC_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 90 01 01 8b 44 24 90 01 01 39 44 24 90 01 01 7d 90 01 01 48 63 44 24 90 01 01 0f b6 44 04 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 99 b9 90 01 04 f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 4c 24 90 01 01 33 c8 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}