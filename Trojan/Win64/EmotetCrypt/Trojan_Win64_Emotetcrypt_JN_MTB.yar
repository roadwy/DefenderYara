
rule Trojan_Win64_Emotetcrypt_JN_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 8f e3 38 8e e3 38 8e e3 41 83 c2 01 49 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 4c 2b c8 4c 03 ce 41 8a 04 29 4d 63 ca 41 32 00 49 83 c0 01 41 88 03 49 83 c3 01 4c 3b cb 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}