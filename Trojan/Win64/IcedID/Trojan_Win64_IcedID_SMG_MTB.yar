
rule Trojan_Win64_IcedID_SMG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 90 01 01 8b 4c 24 48 66 3b c9 90 00 } //1
		$a_03_1 = {0f b6 44 01 90 01 01 8b 4c 24 90 01 01 33 c8 66 3b 90 00 } //1
		$a_03_2 = {8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 e9 90 00 } //1
		$a_00_3 = {88 04 0a e9 } //1
		$a_00_4 = {69 6e 69 74 } //1 init
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_SMG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.SMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 01 eb 4d 63 db 44 01 c2 c1 fa 05 29 c2 0f af d7 29 d1 48 63 c9 41 0f b6 04 0a 42 32 04 06 49 83 c0 01 44 39 c3 43 88 04 19 0f 87 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}