
rule Trojan_Win64_CobaltStrike_DE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 05 e0 4c 8d 48 01 41 32 48 ff 48 63 c2 ff c2 48 03 45 c0 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_DE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 28 0f b6 04 01 89 44 24 30 48 63 4c 24 20 33 d2 48 8b c1 b9 90 01 04 48 f7 f1 48 8b c2 8b 4c 24 30 33 4c 84 40 8b c1 48 63 4c 24 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_DE_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a } //1
		$a_01_1 = {89 ca 83 e2 03 41 0f b6 14 17 32 14 0f 88 14 0b 8d 51 01 83 e2 03 41 0f b6 14 17 32 54 0f 01 88 54 0b 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}