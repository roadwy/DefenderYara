
rule Trojan_Win64_Qakbot_YY_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {49 8b ca 83 e1 90 01 01 49 ff c2 8a 8c 01 90 01 04 43 32 0c 01 41 88 08 49 ff c0 49 83 eb 90 01 01 90 13 48 8b 05 90 00 } //100
		$a_03_2 = {48 8b cb 48 f7 e3 48 8b c3 48 ff c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 90 01 01 48 2b c8 48 8d 05 90 01 04 8a 04 01 43 32 04 08 41 88 01 49 ff c1 48 83 ee 01 90 13 48 b8 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100) >=201
 
}