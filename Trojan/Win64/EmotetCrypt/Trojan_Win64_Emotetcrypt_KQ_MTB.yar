
rule Trojan_Win64_Emotetcrypt_KQ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 d1 0f b6 4c 15 20 48 8b 15 90 01 04 44 8b 45 f8 89 45 bc 44 89 c0 48 89 55 b0 99 44 8b 45 bc 41 f7 f8 4c 63 ca 4c 8b 55 b0 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d 90 01 04 8b 4d f8 8b 55 fc 0f af 95 90 01 04 29 d1 48 63 f1 45 88 1c 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}