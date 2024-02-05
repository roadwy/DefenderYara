
rule Trojan_Win64_Emotetcrypt_MD_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 f9 48 69 f7 90 01 04 48 89 f2 48 c1 ea 90 01 01 48 c1 fe 90 01 01 01 d6 6b d6 90 01 01 29 d7 48 63 d7 42 0f b6 14 02 32 14 0b 88 14 08 48 ff c1 8b 95 90 01 04 48 39 d1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}