
rule Trojan_Win64_Emotetcrypt_EA_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8b 4c 24 20 0f b6 04 01 89 44 24 04 48 63 0c 24 33 d2 48 8b c1 48 f7 74 24 40 48 8b c2 } //5
		$a_01_1 = {48 63 c9 48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}