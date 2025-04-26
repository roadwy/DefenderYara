
rule Trojan_Win64_IcedID_IH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.IH!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {89 84 24 c0 00 00 00 48 63 4c 24 44 66 3b d2 74 55 33 c8 8b c1 66 3b ed 74 3a } //1
		$a_01_1 = {48 63 4c 24 44 48 8b 94 24 a0 00 00 00 e9 ac 04 00 00 } //1
		$a_01_2 = {88 04 0a e9 } //1
		$a_01_3 = {8b 44 24 44 e9 2a ff ff ff } //1
		$a_01_4 = {ff c0 89 44 24 44 e9 } //1
		$a_01_5 = {70 69 6e 67 } //1 ping
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}