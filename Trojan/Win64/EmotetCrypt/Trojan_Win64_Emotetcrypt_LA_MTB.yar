
rule Trojan_Win64_Emotetcrypt_LA_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb 48 8d 7f 90 01 01 f7 eb 03 d3 ff c3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 8b 05 90 01 04 48 63 d1 0f b6 0c 02 41 32 4c 3e ff 88 4f ff 48 ff ce 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}