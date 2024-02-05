
rule Trojan_Win64_Emotetcrypt_KG_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 85 90 01 04 48 8d 0c 02 8b 85 90 01 04 48 98 44 0f b6 44 05 a0 4c 8b 0d 90 01 04 8b 85 90 01 04 99 c1 ea 1b 01 d0 83 e0 1f 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 90 01 04 01 8b 85 90 01 04 3b 85 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}