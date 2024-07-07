
rule Trojan_Win64_CobaltStrike_BR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 58 41 8b c3 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 8d 04 92 3b c8 8b 44 24 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BR_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 68 39 c3 7e 16 48 89 c2 83 e2 07 41 8a 54 15 00 32 14 07 88 14 01 48 ff c0 eb } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_CobaltStrike_BR_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 14 90 01 01 48 8d 52 90 01 01 34 90 01 01 ff c1 88 84 15 90 01 04 81 f9 90 01 04 72 90 00 } //1
		$a_03_1 = {f3 0f 6f 4c 04 90 01 01 f3 0f 7f 84 90 02 0a 66 0f ef cc 66 0f ef cb 66 0f ef ca f3 0f 7f 8c 90 01 05 81 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}