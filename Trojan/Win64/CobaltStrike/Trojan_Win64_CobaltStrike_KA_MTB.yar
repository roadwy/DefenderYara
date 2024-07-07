
rule Trojan_Win64_CobaltStrike_KA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c8 41 8b d2 d3 ea 8a 08 48 8b 47 90 01 01 80 f1 90 01 01 22 d1 48 63 8f 90 01 04 88 14 01 ff 87 90 01 04 45 85 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_KA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 48 8b 4d 30 41 b8 00 30 00 00 ff 15 } //1
		$a_03_1 = {8b 13 8b 4b f8 49 90 01 02 44 8b 43 fc 48 03 ce e8 90 01 04 0f b7 45 06 48 8d 5b 28 ff c7 3b f8 7c 90 00 } //1
		$a_01_2 = {0f 10 02 42 0f 10 4c 02 f0 0f 11 01 42 0f 11 4c 01 f0 48 8b c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}