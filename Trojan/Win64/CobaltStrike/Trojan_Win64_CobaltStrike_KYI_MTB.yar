
rule Trojan_Win64_CobaltStrike_KYI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 c3 f0 42 80 34 30 79 ff c3 81 fb 3f b0 04 00 } //1
		$a_01_1 = {33 d2 89 5c 24 28 48 8b c8 41 b9 00 10 00 00 c7 44 24 20 04 00 00 00 41 b8 00 00 c1 12 41 ff d5 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_Win64_CobaltStrike_KYI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 07 28 00 2a 00 48 8d 05 c3 1b 00 00 c7 45 c7 30 00 00 00 48 89 45 0f 4c 8d 45 c7 48 8d 45 07 48 89 5d cf 0f 57 c0 48 89 45 d7 8d 53 0d c7 45 df 40 00 00 00 48 8d 4d bf f3 0f 7f 45 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}