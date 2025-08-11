
rule Trojan_Win64_CryptInject_CCJX_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 c0 03 00 00 41 b8 02 00 00 00 ba 00 00 00 00 48 89 c1 e8 7f 1b 00 00 48 8b 85 c0 03 00 00 48 89 c1 e8 78 1b 00 00 89 85 bc 03 00 00 48 8b 85 c0 03 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 e8 50 1b 00 00 8b 85 bc 03 00 00 48 98 48 89 c1 e8 18 1c 00 00 } //1
		$a_01_1 = {48 63 d0 48 8b 85 b0 03 00 00 48 01 d0 0f b6 10 8b 85 cc 03 00 00 48 63 c8 48 8b 85 b0 03 00 00 48 01 c8 83 f2 55 88 10 83 85 cc 03 00 00 01 8b 85 cc 03 00 00 3b 85 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}