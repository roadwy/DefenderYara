
rule Trojan_Win64_CobaltStrike_BQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 89 f1 44 32 0c 0f 44 88 0c 08 48 83 c1 90 01 01 39 cb 7f 90 00 } //1
		$a_03_1 = {41 8b 08 81 e2 90 01 04 48 8d 04 13 4c 01 14 01 eb 90 01 01 45 33 f6 41 8b d6 44 90 01 03 0f 86 90 01 04 8b ca 03 d6 8a 04 29 88 04 19 3b 57 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_BQ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 10 33 48 8d 55 b0 48 8b cb e8 90 02 04 b9 10 00 00 00 0f 1f 40 00 0f 1f 84 00 00 00 00 00 0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 90 00 } //2
		$a_03_1 = {b9 0f 27 00 00 ff 15 90 02 04 4c 89 74 24 20 41 b9 f4 01 00 00 4c 8d 85 60 02 00 00 48 8b 54 24 60 48 8b cf 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}