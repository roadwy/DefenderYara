
rule Trojan_Win64_Emotetcrypt_AM_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ff c3 49 f7 e3 49 8b c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 48 6b c0 3e 4c 2b d8 4c 03 dd 43 8a 04 23 4c 63 db 41 32 00 49 ff c0 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotetcrypt_AM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotetcrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {48 03 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 8b 0d } //03 00 
		$a_01_1 = {48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2 } //00 00 
	condition:
		any of ($a_*)
 
}