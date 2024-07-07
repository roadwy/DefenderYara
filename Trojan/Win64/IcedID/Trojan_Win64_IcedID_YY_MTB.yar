
rule Trojan_Win64_IcedID_YY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {0f b7 44 24 24 66 ff c0 66 89 44 24 24 0f b7 44 24 24 0f b7 4c 24 28 3b c1 7d 90 01 01 0f b7 44 24 24 48 8b 4c 24 40 8a 04 01 88 44 24 20 8b 4c 24 2c e8 90 01 04 89 44 24 2c 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c 24 24 48 8b 54 24 48 88 04 0a 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}