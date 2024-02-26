
rule Trojan_Win64_CryptInject_YAN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 db 31 c9 48 2b 0d 9f d2 06 00 48 81 f1 90 01 04 48 69 c9 90 01 04 48 d1 c1 81 e1 fd ff 00 00 49 be 5e e2 b7 f1 a0 b0 78 b2 4c 33 34 08 0f b6 6c 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}