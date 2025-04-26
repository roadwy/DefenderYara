
rule Trojan_Win64_Emotetcrypt_EB_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c1 48 8b 4c 24 38 0f b6 04 01 8b 4c 24 04 33 c8 8b c1 } //5
		$a_01_1 = {44 03 c1 41 8b c8 03 d1 8b ca } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}