
rule Trojan_Win64_Emotet_BL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 13 ff 41 88 4a ff 48 ff cb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_BL_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 48 63 c9 48 8b 15 90 01 04 88 04 0a e9 90 00 } //3
		$a_01_1 = {03 f9 8b cf 03 d1 8b ca } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Emotet_BL_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e7 8b cf 4d 8d 49 90 01 01 c1 ea 90 01 01 ff c7 6b c2 90 01 01 2b c8 48 63 c1 42 0f b6 0c 10 41 32 49 90 01 01 41 88 48 90 01 01 41 3b fb 7d 90 01 01 4c 8b 15 90 01 04 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}