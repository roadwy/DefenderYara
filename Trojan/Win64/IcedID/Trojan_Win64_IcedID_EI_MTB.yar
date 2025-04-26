
rule Trojan_Win64_IcedID_EI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c0 0f b6 84 04 60 01 00 00 3a ff } //1
		$a_01_1 = {8b 8c 24 8c 00 00 00 33 c8 66 3b d2 } //1
		$a_01_2 = {8b c1 48 63 4c 24 3c } //1
		$a_01_3 = {48 8b 54 24 70 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}