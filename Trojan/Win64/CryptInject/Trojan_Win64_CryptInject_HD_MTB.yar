
rule Trojan_Win64_CryptInject_HD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 14 1a 8d 42 90 01 01 33 c9 3c 90 01 01 b8 90 01 04 0f 46 c8 0a d1 0f be c2 49 33 c0 0f b6 c8 41 c1 e8 90 01 01 48 8d 05 90 01 04 44 33 04 88 48 8b 54 24 90 01 01 41 f7 d0 44 3b 84 24 90 01 04 0f 84 90 01 04 41 80 3b 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}