
rule Trojan_Win64_Emotetcrypt_LJ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 90 01 01 29 c2 89 d0 c1 e0 90 01 01 8d 14 c5 90 02 04 29 c2 89 c8 29 d0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}