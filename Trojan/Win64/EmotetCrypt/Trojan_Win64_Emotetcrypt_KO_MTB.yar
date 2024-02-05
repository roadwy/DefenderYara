
rule Trojan_Win64_Emotetcrypt_KO_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b 45 18 89 45 b4 44 89 c0 48 89 55 a8 99 44 8b 45 b4 41 f7 f8 4c 63 ca 4c 8b 55 a8 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d 90 01 04 8b 4d 18 2b 4d 1c 03 4d 1c 48 63 f1 45 88 1c 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}