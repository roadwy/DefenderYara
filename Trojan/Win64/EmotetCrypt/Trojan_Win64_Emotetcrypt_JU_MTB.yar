
rule Trojan_Win64_Emotetcrypt_JU_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 2b c8 8b 05 90 01 04 0f af 05 90 01 04 48 98 48 2b c8 48 63 05 90 01 04 48 2b c8 48 8b 44 24 48 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d 90 01 04 0f af 0d 90 01 04 8b 04 24 2b c1 03 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 2b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}