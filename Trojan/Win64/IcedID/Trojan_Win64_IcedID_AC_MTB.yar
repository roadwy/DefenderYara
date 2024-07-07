
rule Trojan_Win64_IcedID_AC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 48 63 4c 24 90 01 01 e9 90 01 04 8b 4c 24 90 01 01 33 c8 3a f6 74 90 01 01 89 84 24 90 01 04 48 90 01 04 66 90 01 02 74 90 00 } //1
		$a_03_1 = {48 89 04 24 e9 90 01 04 33 c0 eb 90 01 01 48 90 01 04 48 90 01 04 e9 90 01 04 48 90 01 04 48 90 01 03 48 90 01 04 e9 90 01 04 48 90 01 03 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_AC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 0f b6 00 0f b6 4c 24 40 33 c1 48 8b 4c 24 60 48 8b 54 24 38 48 2b d1 48 8b ca 0f b6 c9 83 e1 08 33 c1 48 8b 4c 24 38 88 01 48 63 44 24 20 48 8b 4c 24 38 48 03 c8 48 8b c1 48 89 44 24 38 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}