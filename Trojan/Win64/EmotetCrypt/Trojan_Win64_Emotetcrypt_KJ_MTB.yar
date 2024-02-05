
rule Trojan_Win64_Emotetcrypt_KJ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 ca 48 6b c9 90 01 01 49 03 c9 0f b6 4c 01 90 01 01 b8 90 01 04 41 32 4c 33 90 01 01 41 f7 e8 88 4e 90 01 01 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 48 8b 05 90 01 04 48 63 ca 48 6b c9 90 01 01 49 03 c9 0f b6 4c 01 90 01 01 32 4c 37 90 01 01 49 83 ec 90 01 01 88 4e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}