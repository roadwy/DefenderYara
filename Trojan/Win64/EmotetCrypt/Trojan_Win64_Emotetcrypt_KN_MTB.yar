
rule Trojan_Win64_Emotetcrypt_KN_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 54 0d 90 01 01 48 8b 0d 90 01 04 44 8b 45 90 01 01 89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 90 01 01 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 90 01 01 41 31 d2 45 88 d3 48 8b 8d 90 01 04 4c 63 4d 90 01 01 46 88 1c 09 8b 45 90 01 01 83 c0 01 89 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}