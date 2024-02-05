
rule Trojan_MacOS_SAgent_ARM_MTB{
	meta:
		description = "Trojan:MacOS/SAgent.ARM!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {09 06 00 94 08 7c 40 93 09 7d d6 9b 29 fd 44 d3 28 a1 17 9b 08 6b 68 38 a8 16 00 38 94 06 00 f1 01 ff ff 54 } //01 00 
		$a_03_1 = {60 42 40 f9 62 22 40 f9 68 32 40 f9 43 00 08 8b 08 00 40 f9 08 15 40 f9 e4 03 00 91 e1 03 14 aa 00 01 3f d6 f5 03 00 aa e8 03 40 f9 60 22 40 f9 16 01 00 cb 63 3e 40 f9 21 00 80 52 e2 03 16 aa 13 03 00 94 1f 00 16 eb 90 01 04 bf 06 00 71 90 00 } //01 00 
		$a_03_2 = {88 32 40 f9 a6 00 08 8b 08 00 40 f9 08 0d 40 f9 e4 23 00 91 e7 43 00 91 e1 03 15 aa 00 01 3f d6 f6 03 00 aa e8 07 40 f9 80 16 40 f9 1f 01 00 eb 90 01 04 df 0e 00 71 90 01 04 df 06 00 71 90 01 04 e8 0b 40 f9 80 22 40 f9 17 01 00 cb 83 3e 40 f9 21 00 80 52 e2 03 17 aa c4 01 00 94 1f 00 17 eb 90 01 04 df 06 00 71 90 01 04 e2 07 40 f9 83 1a 40 f9 82 16 00 f9 83 1e 00 f9 80 42 40 f9 e0 01 00 b4 85 22 40 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}