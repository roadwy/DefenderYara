
rule Trojan_Win64_Emotetcrypt_LT_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 84 04 80 00 00 00 89 44 24 48 8b 44 24 20 99 b9 90 01 04 f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 0d 90 01 04 0f af 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}