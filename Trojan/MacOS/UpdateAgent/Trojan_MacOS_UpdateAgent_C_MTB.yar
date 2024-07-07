
rule Trojan_MacOS_UpdateAgent_C_MTB{
	meta:
		description = "Trojan:MacOS/UpdateAgent.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 e5 48 81 ec f0 00 00 00 c7 45 fc 00 00 00 00 48 8d 35 21 37 00 00 48 8d 45 e0 48 89 c7 48 89 85 28 ff ff ff e8 90 01 03 00 48 8d 7d b0 48 8b b5 28 ff ff ff e8 24 32 00 00 e9 00 00 00 00 48 8d 7d c8 48 8d 75 b0 e8 12 f8 ff ff e9 00 00 00 00 90 00 } //2
		$a_03_1 = {48 89 e5 48 89 7d f8 40 80 e6 01 40 88 75 f7 48 8b 45 f8 f6 45 f7 01 48 89 45 e8 0f 90 01 04 00 48 8b 45 e8 48 8b 48 08 48 8b 10 48 0b 0a 48 89 0a e9 90 01 03 00 48 8b 45 e8 48 8b 48 08 48 81 f1 ff ff ff ff 48 8b 10 48 23 0a 48 89 0a 48 8b 45 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}