
rule Trojan_Win64_Emotetcrypt_LH_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b cb 41 f7 eb 41 03 d3 41 ff c3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 10 41 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}