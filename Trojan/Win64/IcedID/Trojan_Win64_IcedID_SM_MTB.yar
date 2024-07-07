
rule Trojan_Win64_IcedID_SM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 0a e9 90 01 04 e9 90 01 04 8b c1 48 90 01 03 eb 90 01 01 8b 4c 24 90 01 01 33 c8 eb 90 01 01 8b c2 90 00 } //1
		$a_03_1 = {48 81 ec 98 90 01 03 c7 44 24 90 01 05 eb 90 01 01 83 44 24 90 01 02 c7 44 24 90 01 05 e9 90 01 04 8b 04 24 ff c0 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}