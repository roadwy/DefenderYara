
rule Trojan_Win64_Emotetcrypt_EC_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 03 c1 48 63 4c 24 70 48 2b c1 48 8b 4c 24 60 0f b6 04 01 2b 44 24 20 8b 4c 24 04 33 c8 8b c1 } //5
		$a_01_1 = {0f af 54 24 28 03 ca 48 63 c9 48 8b 54 24 50 88 04 0a } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}