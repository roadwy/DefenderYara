
rule Trojan_Win64_Emotetcrypt_MF_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 89 84 24 90 01 04 8b 84 24 90 01 04 99 90 02 0f 48 98 48 8b 8c 24 90 01 04 0f b6 04 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 8c 24 90 01 04 48 8b 94 24 90 01 04 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}